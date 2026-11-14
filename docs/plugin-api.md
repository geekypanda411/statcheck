# Plugin API

## Analyzers

An analyzer is a subclass of `BaseAnalyzer` discovered from
`src/analyzers/*.py` (cross-format) or `src/analyzers/<format>/*.py`.

### Required attributes

| Attribute | Type | Description |
|---|---|---|
| `name` | `str` | Human-readable display name. |
| `supported_formats` | `list[str]` | `"all"` or a subset of `pe`, `elf`, `macho`. |
| `plugin_id` | `str` | Unique id; used for config lookup, dependencies, and output directories. |

### Optional attributes

| Attribute | Default | Description |
|---|---|---|
| `depends` | `{"all": [], "any": []}` | DAG dependencies (see [architecture.md](architecture.md)). |

### The `analyze()` method

```python
def analyze(self, target_file, tool_path, plugin_config, run_dir): ...
```

- `target_file` - `TargetFile` (path, format, results, cached bytes via
  `target_file.read_bytes()`).
- `tool_path` - resolved default tool path (`<bin_path>/<tool or plugin_id>`).
  Use `resolve_tool_path(tool_path)` to resolve it to an existing executable.
- `plugin_config` - the plugin's `tools_config.json` block.
- `run_dir` - absolute run output directory.

### BaseAnalyzer helpers

| Helper | Description |
|---|---|
| `resolve_tool_path(tool_path)` | Module function: configured path, then PATH lookup, else `None`. |
| `run_tool(cmd, timeout=...)` | Module function (`src.core.process`): subprocess with timeout, raises `ToolTimeout`/`ToolError`. |
| `self.resolve_timeout(plugin_config)` | `plugin_config["timeout"]` or the runtime default. |
| `self.get_limit(key)` | Resolved limit (config `limits` over defaults). |
| `self.get_plugin_dir(run_dir)` | Creates/returns `<run_dir>/<plugin_id>/`. |
| `self.save_raw(run_dir, filename, data)` | Writes raw JSON (size-capped) and returns a **run-dir-relative** path. |
| `self.set_runtime(context)` | Called by the orchestrator; `self.runtime` exposes paths/timeout/limits. |

### Publishing results

```python
target_file.add_result(
    self.plugin_id,
    summary_data={...},  # goes to result_summary
    internal_context_data={...},  # goes to internal_context (inter-plugin)
)
target_file.set_plugin_status(plugin_id, status, error=None, duration_ms=None)
```

`add_result` only accepts `summary_data` / `internal_context_data`; anything
else raises `TypeError` (a historical `complete_data=` kwarg once crashed
plugins - raw output now goes through `save_raw`).

### Conventions

1. **Availability**: when the external tool is missing, publish
   `{"status": "unavailable", "reason": ...}` instead of returning silently.
2. **Timeouts**: never call `subprocess.run` directly; use `run_tool` and let
   `ToolTimeout` propagate.
3. **Paths**: every path stored in a summary must be run-dir-relative
   (use `save_raw` / `os.path.relpath`).
4. **Determinism**: convert sets to `sorted(...)`, never `list(set(...))`.
5. **Limits**: cap unbounded lists with `self.get_limit(...)`.
6. **Exceptions**: catch only expected I/O/tool errors; let programming
   errors propagate so the orchestrator records `failed` with a traceback.

## Reporters

A reporter subclasses `BaseReporter` in `src/reporters/`:

| Attribute | Description |
|---|---|
| `name` | Display name. |
| `format_id` | Value matched against `--report` (e.g. `json`, `markdown`). |
| `reporter_id` | Key used in `reporter_config.json`. |

```python
def generate(self, target_file, run_dir, reporter_config, timestamp): ...  # write files into run_dir
```

`reporter_config` is the plugin's reporter_config block (e.g.
`output_template`). Reporters are selected with `--report <format_id> ...`
or `--report all`, and disabled via `reporter_config.json`.
