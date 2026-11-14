# Architecture

## Directory layout

```
main.py                     CLI entry point (also `statcheck` console script)
src/
  core/
    orchestrator.py         Plugin discovery, DAG scheduling, statuses
    target_file.py          Shared per-run result store (summary/context/metadata)
    format_detect.py        Magic-byte format detection
    paths.py                PROJECT_ROOT + CWD-independent path resolution
    config.py               Config validation
    process.py              run_tool(): subprocess helper with timeouts
    cache.py                Cache dir + atomic JSON writes
    http.py                 Shared TI HTTP session + on-disk response cache
    analysis_utils.py       Entropy, MIME magic, deterministic helpers
  analyzers/
    base_analyzer.py        BaseAnalyzer, RuntimeContext, resolve_tool_path, save_raw
    *.py                    Cross-format analyzers
    pe/                     PE-specific analyzers
    elf/                    ELF-specific analyzers
  reporters/
    base_reporter.py        BaseReporter
    json_reporter.py        JSON report (schema_version 1.0)
    markdown_reporter.py    Markdown report
bin/                        External binaries (gitignored)
yara_rules/                 YARA rules (gitignored)
reports/                    Run outputs (gitignored)
tests/                      Pytest suite (no network, no repo writes)
docs/                       Documentation
```

## Execution flow

1. **CLI** (`main.py`) parses arguments, detects/validates the format, and
   builds the `Orchestrator`.
2. **Discovery**: plugin files are imported once per process; duplicate
   class objects and duplicate `plugin_id`s are filtered out, so repeated
   loads are idempotent.
3. **Config validation**: type errors abort (exit 2); unknown keys warn.
4. **Pruning**: plugins disabled via config are marked
   `skipped_disabled`; cascading dependency removal marks dependents
   `skipped_dependency`.
5. **DAG scheduling**: a thread pool (default 10 workers) runs analyzers as
   soon as their dependencies complete. Deadlocks (unsatisfiable
   dependencies) are detected and reported.
6. **Status recording**: each plugin gets `completed` / `failed` /
   `timeout` plus duration in `metadata.plugins`. Failures store the repr and
   a truncated traceback.
7. **Reporting**: each enabled reporter renders `metadata` +
   `result_summary` into the run directory.

## DAG semantics

- `depends = {"all": [...]}`: every listed plugin must be enabled and
  complete first. Missing ones cascade-disable the dependent.
- `depends = {"any": [...]}`: at least one listed plugin must be enabled; the
  dependent then waits for **all enabled** members of the list (so results
  are merged deterministically).

## Result contract

`TargetFile.results` has three sections:

- `result_summary`: per-plugin, high-signal data for humans/LLMs.
- `internal_context`: per-plugin data shared between plugins (e.g. extracted
  strings published to the IOC extractor).
- `metadata`: run info (`run`, `analyzed_by`, `plugins` statuses).

Raw artifacts are written per plugin into `<run_dir>/<plugin_id>/` via
`BaseAnalyzer.save_raw`, which always returns a **run-dir-relative** path so
reports stay portable.

## Runtime context

Before an analyzer is submitted, the orchestrator calls
`analyzer.set_runtime(RuntimeContext(...))` exposing `config_path`,
`run_dir`, `project_root`, `timeout`, and `limits` - without changing the
public `analyze()` signature. Third-party plugins keep working.

## Reliability

- Every external tool call goes through `run_tool()` with a mandatory
  timeout; `ToolTimeout` propagates to the orchestrator (status `timeout`),
  `ToolError` degrades to a `status: unavailable` summary.
- Extraction/output sizes are capped through the `limits` config.
- Ctrl-C cancels queued work (`shutdown(cancel_futures=True)`) and exits
  with code 130; running subprocesses are bounded by their timeout.
