# Statcheck

Statcheck is a modular orchestrator that automates static analysis of binaries
(PE, ELF, Mach-O) using Python plugins that wrap the external tools you
already rely on.

It supports chaining custom analyzers and reporters through a DAG dependency
system, reducing manual intervention. While built with malware analysis and
reverse engineering in mind, the core engine can orchestrate any automated
file-processing pipeline.

> **Security note:** statcheck performs *static* analysis only and never
> executes the sample. Even so, always run it in an isolated VM/container and
> never submit sensitive samples to third-party TI APIs. See
> [docs/security.md](docs/security.md).

## Why Statcheck?

- **Familiar tooling:** choose the external analysis tools you prefer (capa,
  FLOSS, Detect It Easy, YARA, ...) and chain them as needed.
- **Efficiency:** heavy lifting is offloaded to compiled utilities; Python
  only parses and correlates their outputs.
- **Extensibility:** integrate new tools or report formats by writing one
  standard Python class.
- **Custom insights:** parse and correlate raw outputs into metrics that are
  meaningful for your workflow.
- **LLM-ready reporting:** data is split into a high-signal `result_summary`
  and per-plugin raw artifacts, keeping reports readable for humans and
  efficient for AI context windows.

## Features

- **Concurrent execution:** a DAG dependency system runs independent
  analyzers in parallel (`all`/`any` dependency semantics).
- **Format-aware routing:** PE/ELF/Mach-O detection via magic bytes (with
  Java-class/fat-Mach-O disambiguation); only supporting plugins are loaded.
- **Observability:** every run records per-plugin status
  (`completed`/`failed`/`timeout`/`skipped_disabled`/`skipped_dependency`/
  `unavailable`), durations, and run metadata.
- **Bounded execution:** every external tool call has a timeout; extraction
  and output sizes are capped through configurable limits.
- **Deterministic output:** identical inputs produce byte-identical reports
  (sorted collections everywhere, stable section ordering).
- **Resilient threat intelligence:** VirusTotal and MalwareBazaar integrations
  with retries, `Retry-After` handling, and an on-disk response cache.
- **Decoupled reporting:** JSON and Markdown reporters, configurable through
  `reporter_config.json`.

## Installation & setup

Requires Python 3.11+.

```bash
git clone https://github.com/geekypanda411/statcheck.git
cd statcheck
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"        # or: pip install -r requirements.txt
```

External tool binaries live in `bin/` (gitignored) and YARA rules in
`yara_rules/` (also gitignored). Provision them manually or with
`scripts/fetch-tools.sh` - see [bin/README.md](bin/README.md).

Copy the example config and add API keys via `.env` (never commit them):

```bash
cp tools_config.json.example tools_config.json
printf 'MB_API_KEY=...\nVT_API_KEY=...\n' > .env
```

## Usage

```bash
statcheck sample.exe                          # auto-detect format, JSON report
statcheck dumped_payload.bin --format pe      # force a format (dumps, etc.)
statcheck sample.bin --report json markdown   # multiple reporters
statcheck sample.bin --report all             # every enabled reporter
statcheck --list-plugins                      # show analyzers/reporters + tool availability
statcheck sample.exe --workers 4 --timeout 120
```

Useful flags: `--config`, `--reporter-config`, `--output-dir`, `--workers`,
`--timeout`, `--debug`, `--log-file`, `--version`. Exit codes: `0` success,
`1` runtime/analysis failure, `2` usage/config error, `130` interrupted.

Reports are written to `<output-dir>/<name>_<timestamp>/` and contain the
summary report(s) plus one sub-directory of raw artifacts per plugin.

## Writing a plugin (analyzer)

Create a Python file in `src/analyzers/` (or `src/analyzers/pe/` /
`src/analyzers/elf/` for format-specific plugins) that inherits from
`BaseAnalyzer`. The orchestrator discovers it automatically.

```python
import json
from src.analyzers.base_analyzer import BaseAnalyzer, resolve_tool_path
from src.core.process import ToolError, run_tool


class CustomAnalyzer(BaseAnalyzer):
    name = "Custom Tool Analyzer"
    plugin_id = "custom_tool"
    supported_formats = ["all"]

    # 'all': every listed plugin must run first.
    # 'any': at least one listed plugin must be enabled; the analyzer waits
    #        for all enabled ones to finish.
    depends = {"all": [], "any": []}

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        # 1. Resolve and run the external tool (with timeout)
        executable = resolve_tool_path(tool_path)
        if executable is None:
            target_file.add_result(self.plugin_id, summary_data={"status": "unavailable", "reason": "tool not found"})
            return
        try:
            result = run_tool([executable, str(target_file.path)], timeout=self.resolve_timeout(plugin_config))
        except ToolError as e:
            target_file.add_result(self.plugin_id, summary_data={"status": "unavailable", "reason": str(e)})
            return

        # 2. Parse the output into a clean summary
        summary = {"status": "analyzed", "findings": []}

        # 3. Write raw output (run-dir-relative path is returned for you)
        summary["raw_output_path"] = self.save_raw(run_dir, "custom_tool_raw_output.json", json.loads(result.stdout))

        # 4. Publish the summary and optional inter-plugin context
        target_file.add_result(
            self.plugin_id,
            summary_data=summary,
            internal_context_data={"custom_input": [...]},
        )
```

More details: [docs/plugin-api.md](docs/plugin-api.md),
[docs/architecture.md](docs/architecture.md).

## Documentation

- [Configuration reference](docs/configuration.md)
- [Architecture & DAG semantics](docs/architecture.md)
- [Plugin API](docs/plugin-api.md)
- [Report schema](docs/report-schema.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Security](docs/security.md)
- [External tools](bin/README.md)

## Roadmap

- [ ] Execution templates: strict tool chaining via JSON templates.
- [ ] Prompt-injection string detection.
- [ ] OSINT hash search for existing sandbox reports.
- [ ] Internal CTI integrations (MISP, OpenCTI).
- [ ] Dynamic analysis via CAPEv2 submission.
- [ ] STIX 2.1 reporter.

## Contributing

Contributions, issues, and feature requests are welcome - see
[CONTRIBUTING.md](CONTRIBUTING.md) and the
[issues page](https://github.com/geekypanda411/statcheck/issues).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE)
file for details.
