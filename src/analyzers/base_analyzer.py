from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import json
import logging
import os
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

# Default resource limits (Phase 3.4). Overridable via the "limits" section
# of tools_config.json (which feeds RuntimeContext.limits).
DEFAULT_LIMITS = {
    "max_file_bytes": 2 * 1024 ** 3,           # 2 GiB input
    "max_resource_bytes": 100 * 1024 ** 2,     # 100 MiB per extracted artifact
    "max_total_extracted_bytes": 1024 ** 3,    # 1 GiB per run
    "max_raw_json_mb": 512,                    # raw JSON files per plugin
    "max_summary_items": 10000,                # per summary category
    "max_strings": 1_000_000,                  # strings fed to IOC extraction
}


@dataclass(frozen=True)
class RuntimeContext:
    """Immutable per-run context handed to analyzers via set_runtime().

    Lets plugins reach paths, timeouts, and limits without changing the
    public ``analyze()`` signature.
    """
    config_path: Path
    run_dir: Path
    project_root: Path
    timeout: float = 300.0
    limits: dict = field(default_factory=dict)


def resolve_tool_path(tool_path: str) -> str | None:
    """Resolve an external tool executable.

    Order: the configured path if it exists and is executable, then a PATH
    lookup by the configured basename (e.g. ``bin/capa-v10.0.0-linux`` falls
    back to ``capa`` on PATH), else ``None``.
    """
    candidate = Path(tool_path)
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    which = shutil.which(candidate.name)
    if which:
        return which
    return None


class BaseAnalyzer(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def supported_formats(self) -> list:
        pass

    @property
    def plugin_id(self) -> str:
        #Optional: to look up tool path and plugin config in tools_config.json
        return None

    @property
    def depends(self) -> dict:
        """
        Dictionary of plugin_ids this analyzer depends on.
        'all': Strict dependencies. All must be enabled and complete.
        'any': Aggregate dependencies. At least ONE must be enabled. Will wait for all enabled ones to complete.
        """
        return {"all": [], "any": []}

    # Per-run context; None until the orchestrator calls set_runtime().
    runtime: RuntimeContext | None = None

    def set_runtime(self, context: RuntimeContext) -> None:
        self.runtime = context

    def get_limit(self, key: str, default=None):
        """Resolve a limit: runtime/config value first, then DEFAULT_LIMITS."""
        limits = dict(DEFAULT_LIMITS)
        if self.runtime and self.runtime.limits:
            limits.update(self.runtime.limits)
        if default is not None and key not in limits:
            limits[key] = default
        return limits.get(key)

    def resolve_timeout(self, plugin_config: dict) -> float:
        """Per-tool timeout: plugin config overrides the runtime default."""
        timeout = plugin_config.get("timeout")
        if timeout is None and self.runtime is not None:
            timeout = self.runtime.timeout
        try:
            return float(timeout) if timeout is not None else 300.0
        except (TypeError, ValueError):
            logger.warning(f"Invalid timeout value {timeout!r} for {self.plugin_id}; using 300s.")
            return 300.0

    def get_plugin_dir(self, run_dir: str) -> str:
        #Helper to dynamically create and return this plugin's dedicated output folder
        plugin_dir = os.path.join(run_dir, self.plugin_id)
        os.makedirs(plugin_dir, exist_ok=True)
        return plugin_dir

    def save_raw(self, run_dir: str, filename: str, data) -> str:
        """Write raw analyzer output as JSON into this plugin's directory.

        Enforces the ``max_raw_json_mb`` limit: oversized payloads are
        replaced by a stub documenting the truncation. Always returns a path
        **relative to** ``run_dir`` so reports stay portable across machines
        and output locations.
        """
        plugin_dir = self.get_plugin_dir(run_dir)
        path = os.path.join(plugin_dir, filename)

        try:
            text = json.dumps(data, indent=4, default=str)
        except (TypeError, ValueError) as e:
            logger.warning(f"{self.plugin_id}: raw output failed to serialize ({e}); writing error stub.")
            text = json.dumps({"status": "serialization_error", "error": str(e)}, indent=4)

        max_chars = int(self.get_limit("max_raw_json_mb")) * 1024 * 1024
        if len(text) > max_chars:
            logger.warning(
                f"{self.plugin_id}: raw output exceeds max_raw_json_mb "
                f"({len(text) // (1024 * 1024)} MiB); writing truncated stub instead."
            )
            text = json.dumps({
                "status": "truncated",
                "reason": "raw output exceeded max_raw_json_mb limit",
                "approx_size_bytes": len(text),
            }, indent=4)

        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return os.path.relpath(path, start=run_dir)

    @abstractmethod
    def analyze(self, target_file, tool_path: str, plugin_config: dict, run_dir: str):
        pass