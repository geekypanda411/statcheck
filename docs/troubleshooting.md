# Troubleshooting

## Common exit codes

| Code | Meaning |
|---|---|
| 0 | Success, including a report with all analyzers disabled/pruned. |
| 1 | Runtime failure or any analyzer `failed`/`timeout`/`unavailable` status (reports are still attempted). |
| 2 | Usage/config error (bad `--report` value, invalid config types). |
| 130 | Interrupted with Ctrl-C after queued work is cancelled and running analyzers stop/finish. |

## A plugin shows `status: "unavailable"`

The external tool could not be resolved. Check, in order:

1. `tools_config.json` -> `bin_path` (resolved **relative to the config
   file**, not your CWD) and the plugin's `tool` name.
2. That `bin/<tool>` exists and is executable (`chmod +x`).
3. Whether the tool is available on `PATH` by its basename (statcheck falls
   back to this automatically).
4. `statcheck --list-plugins` prints an `External tool availability` section
   showing `OK` / `MISSING` per configured tool.

## A plugin shows `status: "timeout"`

The tool exceeded its timeout (`timeout` key in the plugin config or
`--timeout` default). Raise the limit or check whether the sample makes the
tool hang.

## A plugin shows `status: "failed"`

The analyzer raised an unexpected exception; `metadata.plugins.<id>.error`
contains the repr and a truncated traceback.

## `Unknown report format(s): pdf`

`--report` accepts `format_id` values from `src/reporters/`
(`json`, `markdown`) or `all`. Use `statcheck --list-plugins` to list them.

## Wrong analyzer set runs (format detection)

Use `--format pe|elf|macho` to force a format for obfuscated files or memory
dumps. `unknown` format still runs all cross-format analyzers.

## Config validation errors

Wrong types (e.g. `"enabled": "true"`) abort with exit code 2 and a message
naming the offending key. Unknown plugin ids and unknown top-level keys only
produce warnings.

## `tools_config.json` keeps changing / concurrent runs corrupt the config

As of 0.2.0 the runtime never writes to the config. TLD update metadata and
TI response caches live under `$XDG_CACHE_HOME/statcheck`
(default `~/.cache/statcheck`).

## The TLD list / IOC domains look stale

Delete `<cache>/tlds.txt` and `<cache>/tlds.meta.json` or set
`tldupdatefreqdays` lower. Without network access the IOC extractor falls
back to a small built-in TLD list.

## Reports differ between two runs of the same sample

Whole reports include variable run metadata and generated paths. With the
same input, config, and analyzer/tool results, `result_summary` should still
be deterministic after excluding embedded paths. Otherwise, look for a plugin
emitting unsorted `set(...)` output and file a bug with both reports attached.

## I installed the package and defaults point into site-packages

For a *non-editable* install, pass `--config`, `--reporter-config`, and
`--output-dir` explicitly. The tool config's `bin_path` is resolved relative
to that config; use absolute values for YARA `rule_path` and other resources
kept in the source tree. Alternatively, use an editable install
(`pip install -e .`), which keeps defaults anchored to the checkout.
