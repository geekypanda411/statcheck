"""Determinism tests: two extractions of the same input must match exactly."""

from __future__ import annotations

import json
from types import SimpleNamespace

from src.analyzers.floss_analyzer import FlossAnalyzer
from src.analyzers.iocextractor_analyzer import IOCExtractorAnalyzer
from src.core.target_file import TargetFile

FLOSS_PAYLOAD = {
    "metadata": {"version": "3.2.0", "min_length": 5},
    "analysis": {"enable_decoded": True, "functions": {"analyzed_static": 3}},
    "strings": {
        "decoded": [{"string": s} for s in ["zeta", "alpha", "beta", "beta", "http://a.example/x", "gamma"]],
        "static": [{"string": "C:\\\\Users\\\\evil\\\\run.exe"}, {"string": "alpha"}],
    },
}


def _run_floss(monkeypatch, tmp_path):
    from src.analyzers import floss_analyzer as fa

    target = TargetFile(str(tmp_path / "sample.exe"), "pe")
    run_dir = tmp_path / f"run-{id(target)}"
    run_dir.mkdir()
    monkeypatch.setattr(fa, "resolve_tool_path", lambda p: "/fake/floss")
    monkeypatch.setattr(
        fa, "run_tool", lambda cmd, **kw: SimpleNamespace(stdout=json.dumps(FLOSS_PAYLOAD), returncode=0)
    )
    analyzer = FlossAnalyzer()
    analyzer.analyze(target, tool_path="/x", plugin_config={}, run_dir=str(run_dir))
    return target, run_dir


def _run_ioc(monkeypatch, tmp_path, target):
    from src.analyzers import iocextractor_analyzer as ice

    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    monkeypatch.setattr(ice, "cache_dir", lambda: cache)
    tld_file = tmp_path / "tlds.txt"
    tld_file.write_text("com\nnet\nevil\n")
    (cache / "tlds.meta.json").write_text('{"tldupdatedon": 9999999999, "tld_version": 1}')

    analyzer = IOCExtractorAnalyzer()
    analyzer.analyze(target, tool_path="", plugin_config={"tld_file": str(tld_file)}, run_dir=str(tmp_path / "run"))
    return target


def test_floss_output_is_deterministic(monkeypatch, tmp_path):
    first, _ = _run_floss(monkeypatch, tmp_path)
    strings_a = [i["string"] for i in first.results["internal_context"]["floss"]["ioc_extractor_input"]]
    assert strings_a == sorted(strings_a)

    second, _ = _run_floss(monkeypatch, tmp_path)
    strings_b = [i["string"] for i in second.results["internal_context"]["floss"]["ioc_extractor_input"]]
    assert strings_a == strings_b


def test_ioc_extraction_is_deterministic(monkeypatch, tmp_path):
    target_a, _ = _run_floss(monkeypatch, tmp_path)
    _run_ioc(monkeypatch, tmp_path, target_a)
    summary_a = target_a.results["result_summary"]["iocextractor"]

    target_b, _ = _run_floss(monkeypatch, tmp_path)
    _run_ioc(monkeypatch, tmp_path, target_b)
    summary_b = target_b.results["result_summary"]["iocextractor"]

    assert summary_a == summary_b
    # Every category must be sorted.
    for key in ("regex_urls", "regex_domains", "regex_winfilepath", "regex_unixfilepath"):
        if key in summary_a:
            assert summary_a[key] == sorted(summary_a[key]), f"{key} not sorted"


def test_ioc_extraction_deterministic_under_random_hashseed(tmp_path):
    """Run the pure extraction in subprocesses with different PYTHONHASHSEED
    values and compare the JSON summaries (timestamps excluded)."""
    import subprocess
    import sys
    from pathlib import Path

    script = Path(tmp_path / "extract.py")
    script.write_text(
        "import json, sys\n"
        "sys.path.insert(0, {root!r})\n"
        "from types import SimpleNamespace\n"
        "from src.core.target_file import TargetFile\n"
        "from src.analyzers.iocextractor_analyzer import IOCExtractorAnalyzer\n"
        "from src.analyzers import iocextractor_analyzer as ice\n"
        "strings = ['http://b.example/y', 'http://a.example/x', 'malware.evil.com',\n"
        "           'C:\\\\\\\\Users\\\\\\\\x\\\\\\\\a.exe', '/usr/bin Evil path', '185.220.101.5']\n"
        "target = TargetFile('sample.exe', 'pe')\n"
        "target.results['internal_context']['floss'] = {{\n"
        "    'ioc_extractor_input': [{{'string': s, 'tags': []}} for s in strings]}}\n"
        "tld = {tld!r}\n"
        "analyzer = IOCExtractorAnalyzer()\n"
        "analyzer.analyze(target, '', {{'tld_file': tld}}, {run!r})\n"
        "print(json.dumps(target.results['result_summary'].get('iocextractor', {{}}), sort_keys=True))\n".format(
            root=str(Path(__file__).resolve().parents[1]), tld=str(tmp_path / "tlds.txt"), run=str(tmp_path / "run")
        )
    )
    (tmp_path / "tlds.txt").write_text("com\nnet\nevil\n")

    outputs = []
    for seed in ("0", "1", "random"):
        env_seed = {"PYTHONHASHSEED": seed}
        import os

        env = dict(os.environ, **env_seed)
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, env=env, timeout=60)
        assert result.returncode == 0, result.stderr
        outputs.append(result.stdout)

    assert outputs[0] == outputs[1] == outputs[2], "output differs across PYTHONHASHSEED values"
