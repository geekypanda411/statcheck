from pathlib import Path


class TargetFile:
    def __init__(self, file_path: str, file_format: str = "unknown"):
        self.path = Path(file_path)
        self.filename = self.path.name
        self.format = file_format.lower()
        self.results = {"metadata": {}, "result_summary": {}, "internal_context": {}}
        self._data: bytes | None = None

    def add_result(self, tool_name: str, summary_data=None, internal_context_data=None):
        # use .setdefault() so that if the key gets deleted somehow Python will recreate it on the fly!

        if summary_data is not None:
            self.results.setdefault("result_summary", {})[tool_name] = summary_data

        if internal_context_data is not None:
            self.results.setdefault("internal_context", {})[tool_name] = internal_context_data

    def set_plugin_status(
        self,
        plugin_id: str,
        status: str,
        error: str | None = None,
        duration_ms: float | None = None,
        tool: str | None = None,
    ):
        """Record per-plugin execution status in metadata.plugins.

        Statuses: completed, failed, skipped_disabled, skipped_dependency,
        unavailable, timeout.
        """
        entry = {"status": status}
        if error is not None:
            entry["error"] = error
        if duration_ms is not None:
            entry["duration_ms"] = round(duration_ms, 1)
        if tool is not None:
            entry["tool"] = tool
        self.results.setdefault("metadata", {}).setdefault("plugins", {})[plugin_id] = entry

    def read_bytes(self) -> bytes:
        """Cached full read of the target file (one read per run)."""
        if self._data is None:
            self._data = self.path.read_bytes()
        return self._data

    def read_mmap(self):
        """Memory-map the target file; callers must not keep the mmap alive.

        Falls back to a plain (cached) read when mmap is not possible.
        """
        import mmap

        try:
            # The mmap stays valid after the fd is closed on POSIX platforms.
            with open(self.path, "rb") as f:
                return mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError):
            return self.read_bytes()
