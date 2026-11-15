# Changelog

All notable changes to statcheck are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
semantic versioning.

## [0.2.0] - 2026-11-14

### Fixed
- `add_result(complete_data=...)` TypeError on the QuantumStrand no-strings
  path; raw output is now always written via `save_raw`.
- Duplicate analyzer/reporter registration on repeated loads (idempotent
  discovery, plugin-id dedupe).
- capa `KeyError` when the tool is missing or returns invalid JSON; guarded
  parsing plus `status` summaries.
- diec ignoring the configured tool path and crashing on missing keys.
- Resource/Overlay analyzer dropping `raw_output_path` from summaries,
  empty raw files, and resource filename collisions across languages.
- MalwareBazaar `IndexError` on empty `data` responses; 429 added to the
  retry list.
- VirusTotal unencoded fuzzy-search URLs and unconditional 20 s sleeps
  before every relation request.
- Config fallback namespace mismatch (`tools` vs `plugins`).
- CWD-dependent default paths (project-root anchored everywhere).
- Invalid `--report` values silently producing no output (now exit 2);
  analyzer `failed`/`timeout`/`unavailable` statuses now produce exit 1 after
  reporting, and reports are generated even when all analyzers are disabled.
- IOC extractor mutating `tools_config.json` at runtime (metadata moved to
  the cache dir).
- Java class files (`CAFEBABE`) being misdetected as fat Mach-O.
- CLI typo (`statchec`) and misleading error/log messages.

### Added
- Per-plugin status metadata (`completed`/`failed`/`timeout`/
  `skipped_disabled`/`skipped_dependency`/`unavailable`) and run metadata.
  Run directories include a UUID suffix to avoid same-second collisions.
- `src/core/process.py`: shared `run_tool()` helper - every external tool
  call has a timeout, and timed-out process trees are killed.
- Configurable resource limits (central input size, captured tool output,
  extraction, raw output, string counts).
- Expanded CLI: `--config`, `--reporter-config`, `--output-dir`, `--workers`,
  `--timeout`, `--version`, `--list-plugins`, `--format` defaults to `auto`;
  documented exit codes (0/1/2/130).
- Config validation with clear errors (type) and warnings (unknown keys).
- `RuntimeContext` for analyzers (paths, timeout, limits) without changing
  the `analyze()` signature.
- Markdown reporter.
- Deterministic `result_summary` ordering across `PYTHONHASHSEED` values and
  thread schedules, excluding run metadata and generated paths.
- Single-pass Shannon entropy; cached target-file bytes; YARA compile cache.
- Lock-protected on-disk TI response caches with TTL pruning and a
  1024-entry cap per provider; retrying MalwareBazaar HTTP session.
- Authenticode validity/digest/timestamp info; ELF hardening flags
  (PIE/NX/RELRO/canary); PE section and entry-point anomaly checks.
- Test suite (140+ tests, no network), ruff/mypy/pytest configuration,
  Makefile, CI workflow, pre-commit hooks.
- Documentation: configuration, architecture, plugin API, report schema,
  troubleshooting, security; bin/README.md; fetch-tools script.

### Changed
- Reports use `schema_version: "1.0"` and run-dir-relative artifact paths.
- TLD lists and TI caches live under `$XDG_CACHE_HOME/statcheck`.
- `tools_config.json.example` refreshed: current tool versions, all plugins,
  limits section.

## [0.1.0] - 2026-08-14

Initial public structure: plugin orchestrator, DAG scheduling, JSON
reporting, PE/ELF analyzers, capa/diec/FLOSS/QuantumStrand/YARA/TI plugins.
