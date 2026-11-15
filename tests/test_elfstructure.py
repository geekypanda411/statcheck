"""Focused regressions for ELF linkage and interpreter reporting."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.analyzers.elf import elfstructure_analyzer as esa
from src.core.target_file import TargetFile


@pytest.fixture()
def analyzer():
    return esa.ELFStructureAnalyzer()


def _fake_elf(*, libraries, has_interpreter, interpreter="", file_type="EXEC", entrypoint=0x1000):
    segment = SimpleNamespace(
        type="LOAD",
        flags=6,
        virtual_address=0,
        virtual_size=0,
    )
    return SimpleNamespace(
        is_pie=False,
        has_nx=True,
        dynamic_symbols=[],
        libraries=libraries,
        has_interpreter=has_interpreter,
        interpreter=interpreter,
        has_section=lambda name: False,
        segments=[segment],
        dynamic_entries=[],
        header=SimpleNamespace(file_type=file_type, entrypoint=entrypoint),
    )


def _run_fake_elf(analyzer, tmp_path, monkeypatch, elf):
    monkeypatch.setattr(esa.lief.ELF, "parse", lambda path: elf)
    sample = tmp_path / "sample.elf"
    sample.write_bytes(b"\x7fELF")
    target = TargetFile(str(sample), "elf")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    analyzer.analyze(target, tool_path="", plugin_config={}, run_dir=str(run_dir))
    return target.results["result_summary"]["elfstructure"]


def test_dynamic_shared_object_without_pt_interp_is_not_static(analyzer, tmp_path, monkeypatch):
    elf = _fake_elf(libraries=["libdependency.so"], has_interpreter=False)

    summary = _run_fake_elf(analyzer, tmp_path, monkeypatch, elf)

    assert summary["flags"]["is_statically_linked"] is False
    assert summary["interpreter"] == "None (No PT_INTERP segment)"
    assert summary["imported_libraries"] == ["libdependency.so"]


def test_dependency_free_dynamic_shared_object_is_not_static(analyzer, tmp_path, monkeypatch):
    elf = _fake_elf(libraries=[], has_interpreter=False, file_type="DYN", entrypoint=0)

    summary = _run_fake_elf(analyzer, tmp_path, monkeypatch, elf)

    assert summary["flags"]["is_statically_linked"] is False
    assert summary["interpreter"] == "None (No PT_INTERP segment)"


def test_no_interpreter_or_dynamic_libraries_remains_static(analyzer, tmp_path, monkeypatch):
    elf = _fake_elf(libraries=[], has_interpreter=False)

    summary = _run_fake_elf(analyzer, tmp_path, monkeypatch, elf)

    assert summary["flags"]["is_statically_linked"] is True
    assert summary["interpreter"] == "None (Statically Linked)"


def test_dynamic_executable_reports_its_actual_interpreter(analyzer, tmp_path, monkeypatch):
    elf = _fake_elf(
        libraries=["libc.so.6"],
        has_interpreter=True,
        interpreter="/lib64/ld-linux-x86-64.so.2",
    )

    summary = _run_fake_elf(analyzer, tmp_path, monkeypatch, elf)

    assert summary["flags"]["is_statically_linked"] is False
    assert summary["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
