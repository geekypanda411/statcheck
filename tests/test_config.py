"""Tests for config loading fallbacks and validation."""

from __future__ import annotations

import json

import pytest

from src.core.config import ConfigError, validate_reporter_config, validate_tool_config
from src.core.orchestrator import Orchestrator


def test_missing_config_uses_plugins_namespace(tmp_path):
    """Regression: fallback used the 'tools' namespace while consumers read 'plugins'."""
    missing = tmp_path / "no-tools-config.json"
    app = Orchestrator(str(tmp_path / "x.bin"), "pe", str(missing), str(tmp_path / "no-reporter-config.json"))

    assert "plugins" in app.config, "fallback tool config must expose the 'plugins' namespace"
    assert app.config["plugins"] == {}
    assert "tools" not in app.config
    # Plugin lookups must not blow up on the fallback config.
    assert app.config.get("plugins", {}).get("anything", {}) == {}


def test_missing_reporter_config_uses_reporters_namespace(tmp_path):
    missing = tmp_path / "no-reporter-config.json"
    app = Orchestrator(str(tmp_path / "x.bin"), "pe", str(missing), str(missing))
    assert app.reporter_config == {"reporters": {}}


def test_existing_config_is_loaded(tmp_path):
    import json

    cfg = tmp_path / "tools_config.json"
    cfg.write_text(json.dumps({"bin_path": "./bin", "plugins": {"capa": {"enabled": False}}}))
    app = Orchestrator(str(tmp_path / "x.bin"), "pe", str(cfg), str(tmp_path / "nope.json"))
    assert app.config["plugins"]["capa"]["enabled"] is False


def test_bin_path_resolved_to_absolute(tmp_path):
    cfg = tmp_path / "tools_config.json"
    cfg.write_text('{"bin_path": "./bin", "plugins": {}}')
    app = Orchestrator(str(tmp_path / "x.bin"), "pe", str(cfg), str(tmp_path / "nope.json"))
    assert str(app.bin_dir).startswith("/")


# ------------------------------------------------------------- validation

def test_validate_tool_config_accepts_valid_config():
    config = {
        "bin_path": "./bin",
        "plugins": {"capa": {"enabled": True, "tool": "capa-v10.0.0-linux", "timeout": 120}},
        "limits": {"max_resource_bytes": 1000},
    }
    assert validate_tool_config(config) == []


def test_validate_tool_config_rejects_wrong_types():
    with pytest.raises(ConfigError):
        validate_tool_config({"plugins": "not-a-dict"})
    with pytest.raises(ConfigError):
        validate_tool_config({"plugins": {"capa": "not-a-dict"}})
    with pytest.raises(ConfigError):
        validate_tool_config({"plugins": {"capa": {"enabled": "yes"}}})
    with pytest.raises(ConfigError):
        validate_tool_config({"plugins": {"capa": {"tool": 42}}})
    with pytest.raises(ConfigError):
        validate_tool_config({"plugins": {"capa": {"timeout": "never"}}})
    with pytest.raises(ConfigError):
        validate_tool_config({"bin_path": 123})


def test_validate_tool_config_warns_on_unknown_keys():
    warnings = validate_tool_config({"frobnicate": True, "plugins": {}})
    assert any("frobnicate" in w for w in warnings)


def test_validate_reporter_config_accepts_valid():
    config = {
        "reporters": {
            "json_reporter": {"enabled": True, "output_template": ["fileinfo", "capa"]},
        }
    }
    assert validate_reporter_config(config) == []


def test_validate_reporter_config_rejects_wrong_types():
    with pytest.raises(ConfigError):
        validate_reporter_config({"reporters": {"json_reporter": {"output_template": "fileinfo"}}})
    with pytest.raises(ConfigError):
        validate_reporter_config({"reporters": {"json_reporter": {"enabled": 1}}})


def test_orchestrator_rejects_invalid_config(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"plugins": {"capa": {"enabled": "true"}}}))
    with pytest.raises(ConfigError):
        Orchestrator(str(tmp_path / "x.bin"), "pe", str(bad), str(tmp_path / "nope.json"))
