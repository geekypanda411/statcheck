"""Tests for config loading fallbacks and validation (Phase 2.4 extends this)."""

from __future__ import annotations

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
