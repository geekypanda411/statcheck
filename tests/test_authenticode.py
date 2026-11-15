"""Authenticode regressions using LIEF 1.0's real attribute enums."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.analyzers.pe import authenticode_analyzer as aa
from src.core.target_file import TargetFile


@pytest.fixture()
def analyzer():
    return aa.AuthenticodeAnalyzer()


def _signature(*, authenticated=(), unauthenticated=()):
    signer = SimpleNamespace(
        authenticated_attributes=list(authenticated),
        unauthenticated_attributes=list(unauthenticated),
    )
    return SimpleNamespace(signers=[signer])


def _attribute(attribute_type):
    return SimpleNamespace(type=attribute_type)


def test_pkcs9_signing_time_is_not_an_rfc3161_timestamp(analyzer):
    signing_time = _attribute(aa.lief.PE.Attribute.TYPE.PKCS9_SIGNING_TIME)
    signature = _signature(authenticated=[signing_time])

    info = analyzer._sig_timestamp_info(signature)

    assert info == {"has_timestamp": False, "countersigned": False}


def test_pkcs9_countersignature_is_not_misreported_as_rfc3161(analyzer):
    countersignature = _attribute(aa.lief.PE.Attribute.TYPE.PKCS9_COUNTER_SIGNATURE)
    signature = _signature(unauthenticated=[countersignature])

    info = analyzer._sig_timestamp_info(signature)

    assert info == {"has_timestamp": False, "countersigned": True}


def test_ms_countersignature_detects_rfc3161_timestamp(analyzer):
    timestamp = _attribute(aa.lief.PE.Attribute.TYPE.MS_COUNTER_SIGN)
    signature = _signature(unauthenticated=[timestamp])

    info = analyzer._sig_timestamp_info(signature)

    assert info == {"has_timestamp": True, "countersigned": True}


@pytest.mark.parametrize("parse_error", [None, RuntimeError("bad PE")])
def test_parse_failure_is_unavailable_not_unsigned(analyzer, tmp_path, monkeypatch, parse_error):
    def fail_parse(path):
        if parse_error is not None:
            raise parse_error
        return None

    monkeypatch.setattr(aa.lief.PE, "parse", fail_parse)
    sample = tmp_path / "broken.exe"
    sample.write_bytes(b"MZ not a complete PE")
    target = TargetFile(str(sample), "pe")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    analyzer.analyze(target, tool_path="", plugin_config={}, run_dir=str(run_dir))

    summary = target.results["result_summary"]["authenticode"]
    assert summary["status"] == "unavailable"
    assert summary["is_signed"] is None
    assert "details" in summary


def test_successfully_parsed_unsigned_pe_remains_unsigned(analyzer, tmp_path, monkeypatch):
    monkeypatch.setattr(aa.lief.PE, "parse", lambda path: SimpleNamespace(has_signatures=False))
    sample = tmp_path / "unsigned.exe"
    sample.write_bytes(b"MZ")
    target = TargetFile(str(sample), "pe")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    analyzer.analyze(target, tool_path="", plugin_config={}, run_dir=str(run_dir))

    summary = target.results["result_summary"]["authenticode"]
    assert summary["is_signed"] is False
    assert "status" not in summary
