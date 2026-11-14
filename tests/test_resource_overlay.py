"""Tests for the Resource & Overlay analyzer summary/raw contract.

PE parsing is exercised through a fake ``pefile.PE`` object (no real PE
fixtures needed); ELF behavior is smoke-tested with synthetic bytes where
possible. No network, no writes outside ``tmp_path``.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from src.analyzers.resource_overlay_analyzer import ResourceOverlayAnalyzer
from src.core.target_file import TargetFile


def _res_entry(type_id, id_, lang_id, offset, data):
    """Build a pefile-shaped resource tree node."""
    return SimpleNamespace(
        struct=SimpleNamespace(Id=type_id),
        name=None,
        directory=SimpleNamespace(
            entries=[
                SimpleNamespace(
                    struct=SimpleNamespace(Id=id_),
                    name=None,
                    directory=SimpleNamespace(
                        entries=[
                            SimpleNamespace(
                                struct=SimpleNamespace(Id=lang_id),
                                data=SimpleNamespace(struct=SimpleNamespace(OffsetToData=offset, Size=len(data))),
                            )
                        ]
                    ),
                )
            ]
        ),
    )


class FakePE:
    def __init__(self, entries, image, overlay=None, overlay_offset=0):
        self.DIRECTORY_ENTRY_RESOURCE = SimpleNamespace(entries=entries)
        self._image = image
        self._overlay = overlay
        self._overlay_offset = overlay_offset

    def get_memory_mapped_image(self):
        return self._image

    def get_overlay(self):
        return self._overlay

    def get_overlay_data_start_offset(self):
        return self._overlay_offset


@pytest.fixture()
def analyzer():
    return ResourceOverlayAnalyzer()


def _run_pe(analyzer, tmp_path, monkeypatch, entries, image, overlay=None, config=None):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(image)
    target = TargetFile(str(sample), "pe")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    offset = len(image) - (len(overlay) if overlay else 0)
    fake = FakePE(entries, image, overlay=overlay, overlay_offset=offset)
    monkeypatch.setattr("src.analyzers.resource_overlay_analyzer.pefile.PE", lambda data: fake)
    fake_lief = SimpleNamespace(ELF=SimpleNamespace(parse=lambda b: None))
    monkeypatch.setattr("src.analyzers.resource_overlay_analyzer.lief", fake_lief)

    analyzer.analyze(target, tool_path="", plugin_config=config or {}, run_dir=str(run_dir))
    return target, run_dir


def test_summary_contains_relative_raw_path_and_raw_has_resources(analyzer, tmp_path, monkeypatch):
    image = b"A" * 4096
    entries = [_res_entry(10, 1, 1033, 100, image[100 : 100 + 64])]
    target, run_dir = _run_pe(analyzer, tmp_path, monkeypatch, entries, image)

    summary = target.results["result_summary"]["resource_overlay"]
    raw_rel = summary["raw_output_path"]
    assert not raw_rel.startswith("/"), "raw path must be run-dir relative"
    raw_file = run_dir / raw_rel
    assert raw_file.is_file()

    raw = json.loads(raw_file.read_text())
    assert len(raw["raw_resources"]) == 1
    entry = raw["raw_resources"][0]
    assert entry["type"] == "RT_RCDATA"
    assert entry["id"] == 1
    assert entry["language"] == 1033
    assert entry["size"] == 64

    assert summary["resources"][0]["id"] == 1


def test_resource_filenames_unique_across_languages(analyzer, tmp_path, monkeypatch):
    image = bytes(range(256)) * 32  # entropy 8.0 => is_risk
    # Same type/id in two languages — must not overwrite each other.
    same_id_entries = SimpleNamespace(
        struct=SimpleNamespace(Id=24),
        name=None,
        directory=SimpleNamespace(
            entries=[
                SimpleNamespace(
                    struct=SimpleNamespace(Id=7),
                    name=None,
                    directory=SimpleNamespace(
                        entries=[
                            SimpleNamespace(
                                struct=SimpleNamespace(Id=1033),
                                data=SimpleNamespace(struct=SimpleNamespace(OffsetToData=16, Size=2048)),
                            ),
                            SimpleNamespace(
                                struct=SimpleNamespace(Id=1041),
                                data=SimpleNamespace(struct=SimpleNamespace(OffsetToData=2100, Size=512)),
                            ),
                        ]
                    ),
                )
            ]
        ),
    )
    target, run_dir = _run_pe(analyzer, tmp_path, monkeypatch, [same_id_entries], image)

    summary = target.results["result_summary"]["resource_overlay"]
    extracted = [r["extracted_to"] for r in summary["resources"] if r["extracted_to"]]
    assert len(extracted) == 2, "both high-entropy resources should be extracted"
    assert len(set(extracted)) == 2, f"extracted filenames collide: {extracted}"
    for path in extracted:
        assert not path.startswith("/")
        assert (run_dir / path).is_file()


def test_resource_filename_format(analyzer):
    name = analyzer._resource_filename("RT_RCDATA", "weird/name!", 1033)
    assert name == "rsrc_RT_RCDATA_weird_name__1033.bin"


def test_extraction_respects_size_limits(analyzer, tmp_path, monkeypatch):
    image = b"\xff" * 8192  # high entropy => is_risk
    entries = [_res_entry(10, 1, 1033, 0, image[:8192])]
    config = {"max_resource_bytes": 1024}  # far below the 8192-byte resource
    target, run_dir = _run_pe(analyzer, tmp_path, monkeypatch, entries, image, config=config)

    summary = target.results["result_summary"]["resource_overlay"]
    assert summary["resources"][0]["extracted_to"] is None, "oversized resource must not be extracted"
    assert summary["resources"][0]["size"] == 8192, "resource still documented in summary"


def test_no_resources_still_publishes_raw_contract(analyzer, tmp_path, monkeypatch):
    target, run_dir = _run_pe(analyzer, tmp_path, monkeypatch, [], b"C" * 128, overlay=None)

    summary = target.results["result_summary"]["resource_overlay"]
    assert summary["status"] == "no_resources_or_overlay"
    raw_rel = summary["raw_output_path"]
    assert not raw_rel.startswith("/")
    assert (run_dir / raw_rel).is_file()


def test_guarded_malformed_resource_nodes(analyzer, tmp_path, monkeypatch):
    image = b"D" * 256
    bad = SimpleNamespace(
        struct=SimpleNamespace(Id=3),
        name=None,
        directory=SimpleNamespace(
            entries=[
                SimpleNamespace(struct=SimpleNamespace(Id=9), name=None),  # no .directory
                "garbage-entry",
            ]
        ),
    )
    target, run_dir = _run_pe(analyzer, tmp_path, monkeypatch, [bad], image)
    # No crash; nothing extracted; raw contract still published.
    summary = target.results["result_summary"]["resource_overlay"]
    assert "raw_output_path" in summary
    assert summary.get("status") == "no_resources_or_overlay"


def test_overlay_is_carved_and_sorted(analyzer, tmp_path, monkeypatch):
    image = b"E" * 1024
    overlay = b"\x7fELF" + b"\x00" * 32 + b"MZ" + b"\x00" * 600 + b"This program cannot be run in DOS mode"
    target, run_dir = _run_pe(analyzer, tmp_path, monkeypatch, [], image, overlay=overlay)

    summary = target.results["result_summary"]["resource_overlay"]
    ovl = summary["overlay"][0]
    assert ovl["size"] == len(overlay)
    artifacts = ovl["carved_artifacts"]
    assert len(artifacts) == 2
    offsets = [a["absolute_offset"] for a in artifacts]
    assert offsets == sorted(offsets), "carved artifacts must be sorted deterministically"
    assert ovl["extracted_to"] and not ovl["extracted_to"].startswith("/")
    assert (run_dir / ovl["extracted_to"]).is_file()
