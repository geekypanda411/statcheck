"""Lightweight configuration validation (no external dependencies).

Type errors raise :class:`ConfigError`; suspicious-but-harmless entries
(unknown plugin ids, unknown top-level keys) produce warning strings so the
orchestrator can log them without aborting the run.
"""

from __future__ import annotations

import math


class ConfigError(ValueError):
    """Raised when a configuration file has an invalid structure/type."""


def _check_is_dict(config: dict, what: str) -> None:
    if not isinstance(config, dict):
        raise ConfigError(f"{what} must be a JSON object/dict, got {type(config).__name__}")


def validate_tool_config(config: dict) -> list[str]:
    """Validate a tools_config-style dict.

    Returns a list of human-readable warnings (empty when clean).
    Raises ConfigError on structural/type errors.
    """
    _check_is_dict(config, "Tool config")

    warnings: list[str] = []

    known_top_level = {"bin_path", "plugins", "limits"}
    for key in config:
        if key not in known_top_level:
            warnings.append(f"Unknown top-level key in tool config: '{key}'")

    bin_path = config.get("bin_path")
    if bin_path is not None and not isinstance(bin_path, str):
        raise ConfigError(f"'bin_path' must be a string, got {type(bin_path).__name__}")

    plugins = config.get("plugins")
    if plugins is not None:
        _check_is_dict(plugins, "'plugins'")
        for plugin_id, plugin_config in plugins.items():
            _check_is_dict(plugin_config, f"plugins.{plugin_id}")
            enabled = plugin_config.get("enabled")
            if enabled is not None and not isinstance(enabled, bool):
                raise ConfigError(f"plugins.{plugin_id}.enabled must be a boolean, got {type(enabled).__name__}")
            tool = plugin_config.get("tool")
            if tool is not None and not isinstance(tool, str):
                raise ConfigError(f"plugins.{plugin_id}.tool must be a string, got {type(tool).__name__}")
            timeout = plugin_config.get("timeout")
            if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float))):
                raise ConfigError(f"plugins.{plugin_id}.timeout must be a number, got {type(timeout).__name__}")
            if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
                raise ConfigError(f"plugins.{plugin_id}.timeout must be a finite number greater than zero")

    limits = config.get("limits")
    if limits is not None:
        _check_is_dict(limits, "'limits'")
        for key, value in limits.items():
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ConfigError(f"limits.{key} must be a number, got {type(value).__name__}")
            if not math.isfinite(value) or value <= 0:
                raise ConfigError(f"limits.{key} must be a finite number greater than zero")

    return warnings


def validate_reporter_config(config: dict) -> list[str]:
    """Validate a reporter_config-style dict. Same contract as above."""
    _check_is_dict(config, "Reporter config")

    warnings: list[str] = []

    known_top_level = {"reporters"}
    for key in config:
        if key not in known_top_level:
            warnings.append(f"Unknown top-level key in reporter config: '{key}'")

    reporters = config.get("reporters")
    if reporters is not None:
        _check_is_dict(reporters, "'reporters'")
        for reporter_id, reporter_config in reporters.items():
            _check_is_dict(reporter_config, f"reporters.{reporter_id}")
            enabled = reporter_config.get("enabled")
            if enabled is not None and not isinstance(enabled, bool):
                raise ConfigError(f"reporters.{reporter_id}.enabled must be a boolean, got {type(enabled).__name__}")
            template = reporter_config.get("output_template")
            bad_template = not isinstance(template, list) or not all(isinstance(i, str) for i in template)
            if template is not None and bad_template:
                raise ConfigError(f"reporters.{reporter_id}.output_template must be a list of strings")

    return warnings
