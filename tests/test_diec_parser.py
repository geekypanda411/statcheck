"""Tests for Detect It Easy output parsing and tool resolution guards."""

from __future__ import annotations

from src.analyzers.diec_analyzer import DIEAnalyzer
from src.core.target_file import TargetFile

VALID_PAYLOAD = {
    "diec-info": {
        "data": {
            "Info": {
                "File type": "PE32",
                "MIME": "application/x-dosexec",
                "Architecture": "x86",
                "Mode": "32",
                "Size": "1024",
            }
        }
    },
    "diec-entropy": {"total": 6.31, "status": "not packed"},
    "diec-packer": {
        "detects": [
            {
                "filetype": "PE32",
                "values": [
                    {"type": "compiler", "string": "MSVC"},
                    {"type": "linker", "string": "9.0"},
                ],
            }
        ]
    },
}


def _analyzer():
    return DIEAnalyzer()


def test_parse_valid_payload():
    out = _analyzer().parse_analyzer_output(VALID_PAYLOAD)
    assert out["File_Type"] == "PE32"
    assert out["File_MIME_Type"] == "application/x-dosexec"
    assert out["File_Arch"] == "x86"
    assert out["File_Mode"] == "32"
    assert out["File_Size"] == "1024"
    assert out["File_Entropy"] == 6.31
    assert out["File_Packing_Status"] == "not packed"
    assert out["File_Toolchain"]["toolchain_PE32"] == [
        {"type": "compiler", "string": "MSVC"},
        {"type": "linker", "string": "9.0"},
    ]


def test_parse_empty_dict():
    assert _analyzer().parse_analyzer_output({}) == {}


def test_parse_missing_packer_key():
    """Regression: raw_results_dict['diec-packer']['detects'] raised KeyError."""
    partial = {"diec-info": VALID_PAYLOAD["diec-info"]}
    out = _analyzer().parse_analyzer_output(partial)
    assert out["File_Type"] == "PE32"
    assert "File_Toolchain" not in out


def test_parse_malformed_detects():
    payload = {"diec-packer": {"detects": ["not-a-dict", {"values": [{"type": "x"}]}, None]}}
    out = _analyzer().parse_analyzer_output(payload)
    # Malformed entries are skipped without raising; missing filetype is dropped.
    assert out == {}


def test_parse_non_dict_packer_block():
    assert _analyzer().parse_analyzer_output({"diec-packer": "oops"}) == {}


def test_parse_non_dict_info_path():
    out = _analyzer().parse_analyzer_output({"diec-info": "oops"})
    assert "File_Type" not in out


def test_missing_tool_returns_unavailable_status(tmp_path):
    target = TargetFile(str(tmp_path / "x.bin"), "pe")
    _analyzer().analyze(
        target,
        tool_path="/nonexistent/path/diec-never-installed",
        plugin_config={},
        run_dir=str(tmp_path / "run"),
    )
    summary = target.results["result_summary"]["diec"]
    assert summary["status"] == "unavailable"
    assert "reason" in summary
