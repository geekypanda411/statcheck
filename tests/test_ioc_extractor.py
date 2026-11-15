"""Tests for the IOC extractor: TLD update flow and regex extraction.

No network: ``requests.get`` is monkeypatched. No repo writes: the cache dir
is redirected into ``tmp_path`` and tools_config.json is verified to stay
byte-identical.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.analyzers.iocextractor_analyzer import IOCExtractorAnalyzer
from src.core.target_file import TargetFile

IANA_BODY = "# Version 2026081400\ncom\nnet\norg\nevil\ngov\n"


@pytest.fixture()
def analyzer():
    return IOCExtractorAnalyzer()


@pytest.fixture()
def fake_cache(tmp_path, monkeypatch):
    import src.core.cache as cache

    cache_location = tmp_path / "cache"
    cache_location.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(cache, "cache_dir", lambda: cache_location)
    # The analyzer imports the names directly; patch there too.
    monkeypatch.setattr("src.analyzers.iocextractor_analyzer.cache_dir", lambda: cache_location)
    return cache_location


def _patch_iana(monkeypatch, body=IANA_BODY, status=200):
    from src.analyzers import iocextractor_analyzer as ice

    monkeypatch.setattr(
        ice.requests,
        "get",
        lambda url, timeout: SimpleNamespace(status_code=status, text=body),
    )


def test_tld_update_never_writes_tools_config(analyzer, fake_cache, monkeypatch, tmp_path):
    """Regression: the old implementation wrote tldupdatedon back into
    tools_config.json, corrupting concurrent runs."""
    config_file = tmp_path / "tools_config.json"
    config_payload = {
        "bin_path": "./bin",
        "plugins": {"iocextractor": {"tld_file": str(tmp_path / "tlds.txt")}},
    }
    import json

    config_file.write_text(json.dumps(config_payload, indent=4))
    before = config_file.read_bytes()

    # Make the updater believe the list is stale.
    monkeypatch.chdir(tmp_path)
    plugin_config = {"tld_file": str(tmp_path / "tlds.txt"), "tldupdatedon": 0}

    _patch_iana(monkeypatch)
    tlds = analyzer._update_tld_list(plugin_config)

    assert config_file.read_bytes() == before, "tools_config.json must never be modified at runtime"
    assert "com" in tlds and "evil" in tlds
    assert (tmp_path / "tlds.txt").exists()
    # Freshness metadata moved to the cache dir, not the config.
    assert (fake_cache / "tlds.meta.json").exists()


def test_tld_list_reused_when_fresh(analyzer, fake_cache, monkeypatch, tmp_path):
    from src.analyzers import iocextractor_analyzer as ice

    tld_file = tmp_path / "tlds.txt"
    tld_file.write_text("com\nnet\n")
    (fake_cache / "tlds.meta.json").write_text('{"tldupdatedon": 9999999999, "tld_version": 1}')

    calls = []
    monkeypatch.setattr(
        ice.requests,
        "get",
        lambda url, timeout: calls.append(url) or SimpleNamespace(status_code=200, text=IANA_BODY),
    )
    tlds = analyzer._update_tld_list({"tld_file": str(tld_file)})
    assert tlds == ["com", "net"]
    assert calls == [], "fresh TLD metadata must skip the network call"


def test_default_tld_file_lives_in_cache_dir(analyzer, fake_cache):
    path = analyzer._tld_file_path({})
    assert path == fake_cache / "tlds.txt"


def test_relative_tld_file_is_project_root_relative(analyzer, fake_cache):
    from src.core.paths import PROJECT_ROOT

    path = analyzer._tld_file_path({"tld_file": "./bin/tlds.txt"})
    assert path == (PROJECT_ROOT / "bin" / "tlds.txt").resolve()


def _run_extract(analyzer, tmp_path, strings_by_source, config=None):
    target = TargetFile(str(tmp_path / "sample.bin"), "pe")
    for source, strings in strings_by_source.items():
        target.results["internal_context"][source] = {
            "ioc_extractor_input": [{"string": s, "tags": tags} for s, tags in strings]
        }
    plugin_config = {"tld_file": str(tmp_path / "fresh-tlds.txt")}
    if config:
        plugin_config.update(config)
    # Pre-seed the TLD list so no network is attempted.
    (tmp_path / "fresh-tlds.txt").write_text("com\nnet\norg\nevil\n")
    analyzer.analyze(target, tool_path="", plugin_config=plugin_config, run_dir=str(tmp_path / "run"))
    return target


def test_ioc_extraction_extracts_urls_ips_domains(analyzer, fake_cache, monkeypatch, tmp_path):
    # Fresh TLD metadata prevents any network access.
    (fake_cache / "tlds.meta.json").write_text('{"tldupdatedon": 9999999999, "tld_version": 1}')
    _patch_iana(monkeypatch)  # belt & braces

    target = _run_extract(
        analyzer,
        tmp_path,
        {
            "floss": [
                ("http://evil.example.com/payload.bin", []),
                ("Visit malware.evil.com", []),
                ("C2 at 185.220.101.5", []),
                ("deadbeef", []),
            ],
        },
    )
    summary = target.results["result_summary"]["iocextractor"]
    assert "http://evil.example.com/payload.bin" in summary["regex_urls"]
    assert "malware.evil.com" in summary["regex_domains"]
    assert "185.220.101.5" in summary["regex_ip"]


def test_domain_boundaries_do_not_drop_iocs_or_match_longer_domains(analyzer, fake_cache, tmp_path):
    (fake_cache / "tlds.meta.json").write_text('{"tldupdatedon": 9999999999, "tld_version": 1}')
    samples = [
        "c2-path.evil.com/path",
        "c2-period.evil.com.",
        "c2-query.evil.com?x=1",
        '"c2-quote.evil.com"',
        "c2-fragment.evil.com#tag",
        "c2-port.evil.com:8080",
        "c2-space.evil.com now",
        "unknown.evil.com.invalid",
    ]
    target = _run_extract(analyzer, tmp_path, {"floss": [(sample, []) for sample in samples]})

    summary = target.results["result_summary"]["iocextractor"]
    assert set(summary["regex_domains"]) == {
        "c2-path.evil.com",
        "c2-period.evil.com",
        "c2-query.evil.com",
        "c2-quote.evil.com",
        "c2-fragment.evil.com",
        "c2-port.evil.com",
        "c2-space.evil.com",
    }
    assert "c2-path.evil.com/path" not in summary.get("regex_unixfilepath", [])


def test_ioc_extraction_ignores_tagged_strings(analyzer, fake_cache, monkeypatch, tmp_path):
    (fake_cache / "tlds.meta.json").write_text('{"tldupdatedon": 9999999999, "tld_version": 1}')
    target = _run_extract(
        analyzer,
        tmp_path,
        {
            "floss": [
                ("http://good.example.com/winapi-thing", ["#winapi"]),
            ],
        },
    )
    # #winapi-tagged strings are excluded by default ignore_tags.
    assert "iocextractor" not in target.results["result_summary"]


# ---------------------------------------------- Phase 5.5 behavior coverage


def _extract_strings(analyzer, fake_cache, tmp_path, strings, config=None):
    (fake_cache / "tlds.meta.json").write_text('{"tldupdatedon": 9999999999, "tld_version": 1}')
    target = _run_extract(analyzer, tmp_path, {"floss": [(s, []) for s in strings]}, config=config)
    return target.results["result_summary"].get("iocextractor", {})


def test_domain_followed_by_punctuation_is_extracted(analyzer, fake_cache, monkeypatch, tmp_path):
    summary = _extract_strings(
        analyzer,
        fake_cache,
        tmp_path,
        [
            "beacon from c2.evil.com, then sleep",
            "backup host c2backup.evil.com); done",
        ],
    )
    assert "c2.evil.com" in summary["regex_domains"]
    assert "c2backup.evil.com" in summary["regex_domains"]


def test_domain_followed_by_whitespace_or_port_is_extracted(analyzer, fake_cache, tmp_path):
    summary = _extract_strings(
        analyzer,
        fake_cache,
        tmp_path,
        [
            "connect to c2-space.evil.com then sleep",
            "connect to c2-port.evil.com:8443 for commands",
        ],
    )
    assert summary["regex_domains"] == ["c2-port.evil.com", "c2-space.evil.com"]


def test_string_cap_is_independent_of_producer_order(analyzer, fake_cache, monkeypatch, tmp_path):
    (fake_cache / "tlds.meta.json").write_text('{"tldupdatedon": 9999999999, "tld_version": 1}')
    original_get_limit = analyzer.get_limit
    monkeypatch.setattr(
        analyzer,
        "get_limit",
        lambda key, default=None: 2 if key == "max_strings" else original_get_limit(key, default),
    )

    forward = _run_extract(
        analyzer,
        tmp_path,
        {
            "floss": [("z.evil.com", []), ("a.evil.com", [])],
            "quantumstrand": [("m.evil.com", []), ("b.evil.com", [])],
        },
    )
    reversed_order = _run_extract(
        analyzer,
        tmp_path,
        {
            "quantumstrand": [("b.evil.com", []), ("m.evil.com", [])],
            "floss": [("a.evil.com", []), ("z.evil.com", [])],
        },
    )

    expected = {"regex_domains": ["a.evil.com", "b.evil.com"]}
    assert forward.results["result_summary"]["iocextractor"] == expected
    assert reversed_order.results["result_summary"]["iocextractor"] == expected


def test_known_false_positives_are_not_iocs(analyzer, fake_cache, monkeypatch, tmp_path):
    summary = _extract_strings(
        analyzer,
        fake_cache,
        tmp_path,
        [
            "dead:beef",
            "/opt/tools/file.zip",
            "0.0.0",
        ],
    )
    assert summary.get("regex_ip") is None, f"dead:beef/0.0.0 must not be IPs: {summary.get('regex_ip')}"
    assert summary.get("regex_domains") is None, (
        f"path-embedded file.zip must not be a domain: {summary.get('regex_domains')}"
    )
    # The unix path is extracted instead.
    assert "/opt/tools/file.zip" in summary["regex_unixfilepath"]


def test_exclude_private_ips_option(analyzer, fake_cache, monkeypatch, tmp_path):
    summary = _extract_strings(
        analyzer,
        fake_cache,
        tmp_path,
        ["dial 185.220.101.5 or 127.0.0.1 or 192.168.1.10, ok"],
        config={"exclude_private_ips": True},
    )
    ips = summary["regex_ip"]
    assert "185.220.101.5" in ips
    assert "127.0.0.1" not in ips
    assert "192.168.1.10" not in ips


def test_exclude_private_ips_off_by_default(analyzer, fake_cache, monkeypatch, tmp_path):
    summary = _extract_strings(
        analyzer,
        fake_cache,
        tmp_path,
        ["dial 127.0.0.1 and 10.0.0.5, ok"],
    )
    assert "127.0.0.1" in summary["regex_ip"]
    assert "10.0.0.5" in summary["regex_ip"]


def test_defang_option(analyzer, fake_cache, monkeypatch, tmp_path):
    summary = _extract_strings(
        analyzer,
        fake_cache,
        tmp_path,
        ["visit http://evil.example.com/payload now"],
        config={"defang": True},
    )
    assert "hxxp://evil[.]example[.]com/payload" in summary["regex_urls"]


def test_tld_pattern_escapes_and_chunks():
    pattern = IOCExtractorAnalyzer._build_tld_pattern(["com", "ne.t", "org"])
    # Dots inside TLDs must be escaped.
    assert "ne\\.t" in pattern
    # Large lists are chunked into groups of 500.
    tlds = [f"tld{i}" for i in range(1200)]
    big = IOCExtractorAnalyzer._build_tld_pattern(tlds, chunk_size=500)
    assert big.count("(?:") >= 3
