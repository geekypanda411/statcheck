# Plugin API

Statcheck has two extension points: **analyzers** produce findings and
**reporters** serialize run results. Both are discovered from Python files;
there is no separate registration file.

Before writing a plugin, read the [architecture guide](architecture.md) for the
run lifecycle and dependency semantics.

## Analyzer discovery

Place a direct `BaseAnalyzer` subclass in:

- `src/analyzers/` for cross-format or conventionally grouped analyzers; or
- `src/analyzers/pe/` / `src/analyzers/elf/` for format-specific analyzers.

Discovery recursively imports all analyzer files. The directory is organizational;
`supported_formats` is the authoritative routing decision. `__init__.py` and
`base_analyzer.py` are skipped, and each `plugin_id` must be unique.

## Required class attributes

| Attribute | Type | Purpose |
|---|---|---|
| `name` | `str` | Human-readable name used in logs and plugin listings. |
| `plugin_id` | `str` | Stable unique ID used for config, dependencies, metadata, and artifact paths. |
| `supported_formats` | `list[str]` | `["all"]` or a subset of `"pe"`, `"elf"`, `"macho"`. |

## Optional class attributes

| Attribute | Default | Purpose |
|---|---|---|
| `depends` | `{"all": [], "any": []}` | IDs that must finish before this analyzer runs. |
| `enabled_by_default` | `True` | Whether absence of `plugins.<id>.enabled` permits execution. Network-facing plugins should use `False`; explicit config still overrides either default. |

A dependency controls **ordering**, not success. Failed/unavailable dependencies
still count as finished, so read inter-plugin context defensively. See
[DAG execution](architecture.md#6-dag-execution).

## The `analyze()` method

```python
def analyze(self, target_file, tool_path, plugin_config, run_dir):
    ...
```

| Argument | Contents |
|---|---|
| `target_file` | `TargetFile` with `path`, `filename`, `format`, `results`, and synchronized `read_bytes()` / `read_mmap()` helpers. |
| `tool_path` | Candidate formed as `<bin_path>/<plugin tool or plugin_id>`. It is not guaranteed to exist. |
| `plugin_config` | This analyzer's `plugins.<plugin_id>` object, or `{}`. Validate plugin-specific values before use. |
| `run_dir` | Unique directory for this run's outputs. It preserves a relative `--output-dir`; call `Path(run_dir).resolve()` when an absolute path is required. |

Immediately before submission, the orchestrator calls `set_runtime()`.
`self.runtime` is a `RuntimeContext` containing:

- `config_path`: resolved active tool-config path;
- `run_dir`: the same run directory as a `Path`;
- `project_root`: base used for project-relative resources;
- `timeout`: CLI/runtime default timeout;
- `limits`: configured global limits.

This preserves the historical `analyze()` signature while giving plugins access
to run-specific policy.

## Helpers

| Helper | Contract |
|---|---|
| `resolve_tool_path(tool_path)` | Return the configured executable if present/executable, then try its basename on `PATH`, otherwise return `None`. |
| `run_tool(cmd, timeout=..., max_output_bytes=...)` | Run an external tool with process-tree cleanup and bounded stdout/stderr. Raises `ToolTimeout`, `ToolError`, or process-creation `OSError`. |
| `self.resolve_timeout(plugin_config)` | Resolve plugin `timeout`, then the runtime default, then 300 seconds. |
| `self.get_limit(key)` | Resolve a configured global limit over built-in defaults. |
| `self.get_plugin_dir(run_dir)` | Create and return `<run_dir>/<plugin_id>/`. |
| `self.save_raw(run_dir, filename, data)` | Serialize raw JSON with a configured size guard and return a run-relative path. Use a trusted fixed filename. |
| `self.set_runtime(context)` | Called by the orchestrator; plugins normally read `self.runtime`, not this method. |

For external tools, pass the configured output limit explicitly:

```python
max_output_bytes = int(self.get_limit("max_tool_output_mb")) * 1024 * 1024
result = run_tool(command, timeout=timeout, max_output_bytes=max_output_bytes)
```

`run_tool()` has its own 512 MiB fallback, but passing the runtime value ensures
that user configuration is respected.

## Complete external-tool analyzer example

```python
import json

from src.analyzers.base_analyzer import BaseAnalyzer, resolve_tool_path
from src.core.process import ToolError, ToolTimeout, run_tool


class CustomAnalyzer(BaseAnalyzer):
    name = "Custom Tool Analyzer"
    plugin_id = "custom_tool"
    supported_formats = ["all"]
    depends = {"all": [], "any": []}

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        executable = resolve_tool_path(tool_path)
        if executable is None:
            target_file.add_result(
                self.plugin_id,
                summary_data={"status": "unavailable", "reason": "tool not found"},
            )
            return

        try:
            result = run_tool(
                [executable, str(target_file.path)],
                timeout=self.resolve_timeout(plugin_config),
                max_output_bytes=int(self.get_limit("max_tool_output_mb")) * 1024 * 1024,
            )
            raw_data = json.loads(result.stdout)
        except ToolTimeout:
            # ToolTimeout subclasses ToolError; re-raise it first so the
            # orchestrator records "timeout" rather than "unavailable".
            raise
        except (ToolError, json.JSONDecodeError) as error:
            target_file.add_result(
                self.plugin_id,
                summary_data={"status": "unavailable", "reason": str(error)},
            )
            return

        raw_path = self.save_raw(run_dir, "custom_tool_raw_output.json", raw_data)
        target_file.add_result(
            self.plugin_id,
            summary_data={
                "status": "analyzed",
                "findings": raw_data.get("findings", []),
                "raw_output_path": raw_path,
            },
            internal_context_data={
                "custom_input": raw_data.get("downstream_strings", []),
            },
        )
```

Process-creation errors and programming bugs should generally propagate. The
orchestrator records them as `failed` with a traceback rather than disguising
them as an unavailable tool.

## Publishing results

Use `TargetFile.add_result()` for both public findings and downstream context:

```python
target_file.add_result(
    self.plugin_id,
    summary_data={"finding_count": 2},          # -> result_summary
    internal_context_data={"strings": [...]},  # -> internal_context
)
```

Only `summary_data` and `internal_context_data` are accepted. Raw payloads belong
in files created by `save_raw()`, not in `internal_context` or oversized report
sections.

### Status ownership

The orchestrator assigns final `metadata.plugins.<id>` status **after**
`analyze()` finishes. Plugins should publish status in their summary and should
not try to override final plugin metadata themselves:

```python
{"status": "unavailable", "reason": "executable not found"}
```

`failed`, `timeout`, and `unavailable` summary statuses are promoted to metadata;
`reason` or `details` becomes the metadata error. Other statuses and a missing
summary normally produce metadata status `completed`.

## Analyzer implementation rules

1. **Availability:** publish `unavailable` with an actionable `reason` for
   expected missing tools, invalid tool output, missing API keys, or unsupported
   input that prevents analysis.
2. **Timeouts:** use `run_tool()` and let `ToolTimeout` propagate. Catch it before
   `ToolError` if both are handled.
3. **Output limits:** pass `max_tool_output_mb` to `run_tool()` and cap unbounded
   lists using `get_limit()`. Sort before taking a deterministic slice.
4. **Artifact paths:** write beneath `run_dir`; publish only run-relative paths.
   For names derived from samples, sanitize every component and verify the
   resolved path remains beneath the intended extraction directory.
5. **Determinism:** convert sets using `sorted(...)`, not `list(set(...))`. Merge
   concurrent inputs before sorting and applying limits.
6. **Exceptions:** catch expected tool/parse/I/O errors deliberately. Let
   unexpected exceptions propagate so failures remain visible.
7. **Concurrency:** assume independent analyzers run simultaneously. Use unique
   plugin IDs/artifact paths and read shared context only after dependencies
   finish.

## Reporter API

Place a direct `BaseReporter` subclass in `src/reporters/` with:

| Attribute | Purpose |
|---|---|
| `name` | Human-readable name. |
| `format_id` | Value matched by `--report`, such as `json` or `markdown`. |
| `reporter_id` | Key in `reporter_config.json`, such as `json_reporter`. |

Implement:

```python
def generate(self, target_file, run_dir, reporter_config, timestamp):
    ...
```

- `target_file.results` contains metadata and public summaries.
- `run_dir` is the unique output directory for this run.
- `reporter_config` is this reporter's block from `reporter_config.json`.
- `timestamp` is the run token; the current orchestrator supplies the string
  `<unix-ts>_<uuid>`. Treat it as an opaque filename component.

`--report` chooses formats to load, and the reporter config can disable one
independently. Propagate write and serialization exceptions: the orchestrator
logs them, attempts remaining reporters, and returns failure rather than silently
claiming success.

See `src/reporters/json_reporter.py` for canonical JSON serialization and
`src/reporters/markdown_reporter.py` for a second implementation of the same
contract.
