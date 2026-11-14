"""Tests for the MalwareBazaar and VirusTotal analyzers (no network).

All HTTP/VT clients are monkeypatched with fakes.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from src.analyzers.malwarebazaar_analyzer import MalwareBazaarAnalyzer
from src.analyzers.vtcheck_analyzer import VirusTotalAnalyzer
from src.core.target_file import TargetFile

# ---------------------------------------------------------------- MalwareBazaar

class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, headers=None, data=None, timeout=None):
        self.calls.append({"url": url, "data": data})
        return self.responses.pop(0)

    def mount(self, *args, **kwargs):
        pass


@pytest.fixture()
def mb_target(tmp_path):
    target = TargetFile(str(tmp_path / "sample.bin"), "pe")
    target.results["result_summary"]["fileinfo"] = {"File_SHA256": "ab" * 32}
    return target


def _run_mb(monkeypatch, tmp_path, mb_target, responses, config=None):
    session = FakeSession(responses)
    monkeypatch.setenv("MB_API_KEY", "test-key")
    monkeypatch.setattr("src.analyzers.malwarebazaar_analyzer.requests.Session", lambda: session)
    analyzer = MalwareBazaarAnalyzer()
    analyzer.analyze(mb_target, tool_path="", plugin_config=config or {}, run_dir=str(tmp_path / "run"))
    return mb_target, session


def test_mb_empty_data_response_is_guarded(monkeypatch, tmp_path, mb_target):
    """Regression: MB 'ok' with empty data used to raise IndexError."""
    payload = {"query_status": "ok", "data": []}
    target, _ = _run_mb(monkeypatch, tmp_path, mb_target, [FakeResponse(200, payload)])
    summary = target.results["result_summary"]["malwarebazaar"]
    assert summary["exact_match"] == "Empty response from MalwareBazaar."


def test_mb_valid_exact_match(monkeypatch, tmp_path, mb_target):
    payload = {
        "query_status": "ok",
        "data": [{
            "signature": "Stealer",
            "tags": ["z", "a"],
            "delivery_method": "email_attachment",
            "file_type": "exe",
            "vendor_intel": {"any.run": {}, "intezer": {}},
            "first_seen": "2026-01-01",
            "yara_rules": ["rule_x"],
        }],
    }
    target, session = _run_mb(monkeypatch, tmp_path, mb_target, [FakeResponse(200, payload)])
    summary = target.results["result_summary"]["malwarebazaar"]
    assert summary["exact_match"]["signature"] == "Stealer"
    assert summary["exact_match"]["tags"] == ["a", "z"]
    # The hash must travel in the POST body, not the URL.
    assert session.calls[0]["data"]["hash"] == "ab" * 32


def test_mb_hash_not_found(monkeypatch, tmp_path, mb_target):
    target, _ = _run_mb(monkeypatch, tmp_path, mb_target, [FakeResponse(200, {"query_status": "hash_not_found"})])
    summary = target.results["result_summary"]["malwarebazaar"]
    assert summary["exact_match"] == "File not found on MalwareBazaar."


def test_mb_missing_api_key_publishes_nothing(monkeypatch, tmp_path, mb_target):
    monkeypatch.delenv("MB_API_KEY", raising=False)
    analyzer = MalwareBazaarAnalyzer()
    analyzer.analyze(mb_target, tool_path="", plugin_config={}, run_dir=str(tmp_path / "run"))
    assert "malwarebazaar" not in mb_target.results["result_summary"]


# ---------------------------------------------------------------- VirusTotal

class FakeAPIError(Exception):
    def __init__(self, code=None):
        super().__init__(code)
        self.code = code


class FakeVTObject:
    def __init__(self, data):
        self._data = data

    def to_dict(self):
        return self._data

    def get(self, key, default=None):
        return self._data.get(key, default)

    @property
    def id(self):
        return self._data.get("id", "id-x")

    @property
    def last_analysis_stats(self):
        return self._data.get("last_analysis_stats", {})


class FakeVTClient:
    def __init__(self, file_obj=None, relation_items=None):
        self.file_obj = file_obj
        self.relation_items = relation_items or []
        self.iterator_calls = []
        self._endpoint_index = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get_object(self, path, *args, **kwargs):
        return self.file_obj

    def iterator(self, path, *args, **kwargs):
        self.iterator_calls.append({"path": path, **kwargs})
        # Only the first relations endpoint yields items in tests.
        if self._endpoint_index == 0 and path.startswith("/files/"):
            self._endpoint_index += 1
            return iter(self.relation_items)
        return iter([])


@pytest.fixture()
def vt_target(tmp_path):
    target = TargetFile(str(tmp_path / "sample.bin"), "pe")
    target.results["result_summary"]["fileinfo"] = {"File_SHA256": "cd" * 32, "File_ssdeep": "3:AAA:BBB"}
    return target


def _run_vt(monkeypatch, tmp_path, vt_target, client, config=None):
    fake_vt = SimpleNamespace(Client=lambda key: client, error=SimpleNamespace(APIError=FakeAPIError))
    monkeypatch.setattr("src.analyzers.vtcheck_analyzer.vt", fake_vt)
    monkeypatch.setenv("VT_API_KEY", "test-key")
    sleep_log = []
    monkeypatch.setattr("src.analyzers.vtcheck_analyzer.time.sleep", lambda s: sleep_log.append(s))
    analyzer = VirusTotalAnalyzer()
    analyzer.analyze(vt_target, tool_path="", plugin_config=config or {}, run_dir=str(tmp_path / "run"))
    return vt_target, sleep_log


def test_vt_exact_match_summary(monkeypatch, tmp_path, vt_target):
    file_obj = FakeVTObject({
        "meaningful_name": "evil.exe",
        "reputation": -5,
        "authentihash": "ef" * 32,
        "first_submission_date": 1700000000,
        "last_analysis_stats": {"malicious": 42},
        "signature_info": {"verified": "no"},
        "crowdsourced_yara_results": [{"rule_name": "x"}],
    })
    client = FakeVTClient(file_obj=file_obj)
    target, sleep_log = _run_vt(monkeypatch, tmp_path, vt_target, client)

    summary = target.results["result_summary"]["vtlookup"]
    assert summary["exact_match"]["malicious_votes"] == 42
    assert summary["exact_match"]["meaningful_name"] == "evil.exe"

    raw_rel = summary["raw_output_path"]
    assert not raw_rel.startswith("/")
    raw = json.loads((tmp_path / "run" / raw_rel).read_text())
    assert raw["exact_hash_match_raw"]["meaningful_name"] == "evil.exe"
    assert sleep_log == [], "exact-match-only runs must not sleep at all"


def test_vt_relations_do_not_sleep_before_first_request(monkeypatch, tmp_path, vt_target):
    relation_item = FakeVTObject({"id": "1.2.3.4"})
    client = FakeVTClient(file_obj=FakeVTObject({"last_analysis_stats": {}}), relation_items=[relation_item])
    config = {
        "fetch_relations_behaviour": True,
        "relations_result_limit": 10,
        "rate_limit_sleep": 7,
    }
    target, sleep_log = _run_vt(monkeypatch, tmp_path, vt_target, client, config=config)

    summary = target.results["result_summary"]["vtlookup"]
    assert summary["relations"]["contacted_ips"] == ["1.2.3.4"]
    # 6 relation endpoints -> sleeps only BETWEEN them (5 sleeps, none first).
    assert sleep_log == [7] * 5, "must sleep between relation requests, not before the first"


def test_vt_fuzzy_query_is_passed_as_param(monkeypatch, tmp_path, vt_target):
    client = FakeVTClient(file_obj=FakeVTObject({"last_analysis_stats": {}}))
    config = {"lookup_fuzzy_hash": True, "fuzzy_lookup_limit": 5}
    target, _ = _run_vt(monkeypatch, tmp_path, vt_target, client, config=config)

    search_calls = [c for c in client.iterator_calls if c["path"] == "/search"]
    assert search_calls, "fuzzy lookup must call the /search endpoint"
    assert search_calls[0]["params"] == {"query": 'ssdeep:"3:AAA:BBB"'}
    # No unencoded query embedded in the URL path.
    assert "?" not in search_calls[0]["path"]


def test_vt_missing_api_key_publishes_nothing(monkeypatch, tmp_path, vt_target):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setattr("src.analyzers.vtcheck_analyzer.vt",
                        SimpleNamespace(Client=lambda key: None, error=SimpleNamespace(APIError=FakeAPIError)))
    analyzer = VirusTotalAnalyzer()
    analyzer.analyze(vt_target, tool_path="", plugin_config={}, run_dir=str(tmp_path / "run"))
    assert "vtlookup" not in vt_target.results["result_summary"]
