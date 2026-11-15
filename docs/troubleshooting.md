# Troubleshooting

## Start with status and reason

For each analyzer, inspect the JSON report in this order:

1. `metadata.plugins.<id>.status` and `metadata.plugins.<id>.error`;
2. `result_summary.<id>.status`, `reason`, or `details` when present;
3. the plugin's `raw_output_path` when present (relative to that run
   directory), and the console/`--log-file` messages.

Markdown reports have a compact **Plugin status** table but omit its detailed
`error` field, so use JSON for diagnosis. `--debug` enables verbose logging;
it also enables strict final JSON serialization, as described in the
[configuration reference](configuration.md).

| Status | Meaning |
|---|---|
| `completed` | The analyzer finished without an orchestrator-detected failure; this does not guarantee findings or optional hashes |
| `skipped_disabled` | Disabled by config; not a run failure |
| `skipped_dependency` | A dependency was disabled/pruned, or a dependency deadlock was detected; only the deadlock itself forces exit 1 |
| `unavailable` | Required input/tool/service was unavailable or output could not be used; forces exit 1 after reporting is attempted |
| `timeout` | An external-tool deadline or YARA engine timeout; forces exit 1 |
| `failed` | An unexpected analyzer exception; `metadata.plugins.<id>.error` contains its repr and a truncated traceback |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Requested enabled reporters completed and no analyzer/deadlock failure was recorded. This includes status-only reports when every analyzer is disabled/pruned |
| 1 | Runtime failure: missing/oversized input, no analyzers for the selected format, analyzer `failed`/`timeout`/`unavailable`, dependency deadlock, reporter write/serialization failure, or another unexpected exception |
| 2 | CLI usage or config error, including invalid config structure/types, unknown requested report format, invalid worker count, or invalid CLI timeout |
| 130 | Ctrl-C; queued work is cancelled and in-flight cleanup is awaited |

Analyzer failures and dependency deadlocks still proceed to the reporting
phase. Early failures such as an oversized target, missing file, no loaded
analyzers, or unknown report format can return before any report exists.

## `unavailable`: find the actual cause

`unavailable` does **not** mean only “executable not found.” Use the reason and
logs to distinguish these cases:

| Cause | What to check |
|---|---|
| Missing TI credential | `api_key_env` names a set, nonempty environment variable (`VT_API_KEY` or `MB_API_KEY` by default). Also confirm the TI block has explicit `"enabled": true` |
| Missing external executable | `bin_path` (relative to the tool config), `tool`, executable permission, then `PATH` lookup of the same basename |
| Tool execution failure | Nonzero exit and stderr summary in `reason`; check tool compatibility and the sample |
| Output cap exceeded | `max_tool_output_mb` applies separately to stdout and stderr for each invocation. The excess is drained/discarded and the analyzer becomes unavailable |
| Invalid tool output | capa, DiE, FLOSS, and QuantumStrand report invalid JSON as unavailable; DiE can retain partial raw results while still marking the analyzer unavailable |
| YARA unavailable | Check that `rule_path` exists, contains `.yar`/`.yara` files when applicable, and compiles/loads. Rule syntax/load failures and YARA engine errors also use `unavailable` |
| Built-in parser unavailable | Inspect `reason` for PE/ELF structure, section, or signature parse failures |

Run `statcheck --list-plugins` for an **External tool availability** preflight.
It checks only config blocks with an explicit string `tool`; `OK` proves path
resolution, not successful execution or parseable output.

An empty capa/DiE result can instead have summary status `no_output`, which is
not one of the orchestrator's failure statuses.

## Timeouts

For capa, DiE, FLOSS, and QuantumStrand, `plugins.<id>.timeout` overrides CLI
`--timeout` (default 300 seconds). Raise it only after checking whether the
sample or tool is hanging. DiE applies the resolved deadline separately to
each subcommand.

YARA is the exception: `plugins.yara_scanner.timeout` defaults to **60 seconds**
and ignores CLI `--timeout`. A YARA `TimeoutError` becomes summary/metadata
status `timeout`, typically with reason `YARA scan exceeded 60s`; optimize the
rules or raise that plugin setting.

TI HTTP request timeouts, retries, and VT/MB pivot sleeps are not governed by
the subprocess timeout settings.

## Oversized input produces no report

If the target exceeds `limits.max_file_bytes` (2 GiB by default), statcheck
exits 1 before format detection or analyzer/tool execution. The error includes
the actual and configured sizes. No run report is generated for this early
rejection; raise the limit deliberately or analyze a smaller input.

## Every analyzer is disabled or dependency-pruned

This is not an error. Statcheck logs that no analyzers can run and generates
status-only reports for each requested, enabled reporter. It exits 0 if report
generation succeeds. If every requested reporter is disabled, there is no
report to write.

This differs from discovering **no analyzers at all** for the selected format,
which exits 1 before reporting.

## Configuration errors and warnings

- Wrong validated non-null types, invalid JSON, non-finite/non-positive
  timeouts or limits, and non-object roots/config blocks exit 2 with the
  offending key where available. Nested `null` is not consistently rejected;
  use documented JSON types because null can instead cause a later analyzer or
  reporter failure (exit 1).
- Unknown top-level keys and unknown analyzer IDs are warnings. Unknown
  reporter IDs, unknown plugin-specific options, and unknown limit names are
  not centrally validated.
- A missing config file warns and uses defaults. TI remains off unless its
  block explicitly contains `"enabled": true`; merely adding a VT/MB block is
  insufficient.
- Relative `bin_path` is based on the config file. Relative YARA `rule_path`
  and IOC `tld_file` are based on the project root, not the caller's CWD.

See [Configuration reference](configuration.md) for the complete validation
and precedence rules.

## `tools_config.json` changes or TLD data looks stale

The runtime never writes `tools_config.json`. Legacy `tldupdatedon` and
`tld_version` entries may still be read as freshness hints, but updates are not
written back to that file.

TLD state is split:

- the list is the configured `tld_file`, or `<cache>/tlds.txt` by default;
- update metadata is always `<cache>/tlds.meta.json`;
- `<cache>` is `$XDG_CACHE_HOME/statcheck` or `~/.cache/statcheck`.

To force a refresh, remove the **actual configured list** and the metadata, or
lower `tldupdatefreqdays`. Ensure a custom list's parent exists and the
destination can be created/written. A missing/stale list triggers an IANA GET
only when IOC extraction
has input strings; no sample data is sent. After a failed download, a readable
existing list remains in use. If no list file exists after the update attempt,
the fallback is `com`, `net`, `org`, `io`, and `xyz`.

## Wrong analyzer set runs

Use `--format pe|elf|macho` to override auto-detection for obfuscated files or
memory dumps. If detection returns `unknown`, only cross-format analyzers run.
Also check `enabled` and dependency statuses before assuming a tool was
selected.

## Unknown report format or missing report

`--report` accepts discovered format IDs (`json`, `markdown`) or `all`; use
`statcheck --list-plugins` to list them. An unknown format exits 2.

During a run, a reporter can be skipped by `"enabled": false`, and any
write/serialization error makes the overall run exit 1. Strict final JSON mode
is enabled by `--debug` or any nonempty `STATCHHECK_STRICT_JSON` value.

## Reports differ between runs

Run timestamps, durations, unique run-directory names, and target paths vary.
Live VT relations/fuzzy searches and MB fuzzy pivots can change even when the
exact-hash response is cached; IANA lists, external tools, and provider data
can also change. Compare only after accounting for those inputs and excluding
variable metadata/paths. With identical analyzer results, summary ordering
should be deterministic.

## Non-editable installs point into site-packages

Pass `--config`, `--reporter-config`, and `--output-dir` explicitly. Put or
point `bin_path` beside the chosen tool config, and use absolute paths for YARA
rules, a custom TLD file, and other source-tree resources. An editable install
(`pip install -e .`) keeps defaults anchored to the checkout.

For provisioning and tool names, see [`bin/README.md`](../bin/README.md).
