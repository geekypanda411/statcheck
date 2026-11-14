"""Tests for the Markdown reporter."""

from __future__ import annotations

from src.core.target_file import TargetFile
from src.reporters.markdown_reporter import MarkdownReporter


def _generate(tmp_path, results=None):
    target = TargetFile(str(tmp_path / "sample.bin"), "pe")
    target.results["metadata"]["analyzed_by"] = ["fileinfo", "iocextractor"]
    target.results["metadata"]["plugins"] = {
        "fileinfo": {"status": "completed", "duration_ms": 12.0},
        "iocextractor": {"status": "completed", "duration_ms": 30.5},
    }
    target.results["metadata"]["run"] = {"format": "pe", "target_filename": "sample.bin"}
    target.results["result_summary"] = results or {
        "fileinfo": {
            "Filename": "sample.bin",
            "File_SHA256": "ab" * 32,
            "raw_output_path": "fileinfo/raw.json",
        },
        "iocextractor": {
            "regex_urls": ["http://evil.example/a", "http://evil.example/b"],
            "regex_ip": [],
        },
    }
    run_dir = tmp_path / "run"
    run_dir.mkdir(exist_ok=True)
    reporter = MarkdownReporter()
    reporter.generate(target, str(run_dir), {}, 1794000000)
    report_file = run_dir / "sample.bin_statcheck_summary_1794000000.md"
    assert report_file.is_file()
    return report_file.read_text()


def test_basic_headings_and_tables(tmp_path):
    text = _generate(tmp_path)
    assert text.startswith("# statcheck report: `sample.bin`")
    assert "## Run" in text
    assert "## Plugin status" in text
    assert "## fileinfo" in text
    assert "## iocextractor" in text
    assert "| fileinfo | completed | 12.0 |" in text
    assert "### File_SHA256" in text
    assert f"`{'ab' * 32}`" in text


def test_raw_paths_are_relative_links(tmp_path):
    text = _generate(tmp_path)
    assert "[fileinfo/raw.json](fileinfo/raw.json)" in text


def test_lists_are_rendered(tmp_path):
    text = _generate(tmp_path)
    assert "- http://evil.example/a" in text
    assert "- http://evil.example/b" in text


def test_empty_lists_are_rendered_as_empty(tmp_path):
    text = _generate(tmp_path)
    assert "*(empty)*" in text


def test_template_ordering_is_respected(tmp_path):
    results = {
        "zeta": {"value": 1},
        "alpha": {"value": 2},
        "fileinfo": {"Filename": "sample.bin"},
    }
    target = TargetFile(str(tmp_path / "s.bin"), "pe")
    target.results["result_summary"] = results
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    reporter = MarkdownReporter()
    reporter.generate(target, str(run_dir), {"output_template": ["fileinfo", "alpha", "zeta"]}, 1)
    text = (run_dir / "s.bin_statcheck_summary_1.md").read_text()
    assert text.index("## fileinfo") < text.index("## alpha") < text.index("## zeta")
