# Report schema

All reporters render the same `TargetFile.results` structure. The JSON
report is canonical; this document describes it.

## Top level

```json
{
    "schema_version": "1.0",
    "metadata": { ... },
    "result_summary": { "<plugin_id>": { ... }, ... }
}
```

- `schema_version`: report contract version (`"1.0"`).
- `result_summary` section order follows the reporter's `output_template`;
  plugins missing from the template are appended in sorted order.

## `metadata`

| Key | Description |
|---|---|
| `run.started_at` / `run.finished_at` / `run.duration_ms` | Wall-clock timing (local time, ISO-8601). |
| `run.target_path` / `run.target_filename` | Analyzed file. |
| `run.format` | Detected/forced format (`pe`, `elf`, `macho`, `unknown`). |
| `run.python_version` | Interpreter version. |
| `analyzed_by` | Sorted list of plugin ids that completed. |
| `plugins` | Per-plugin status entries (below). |

### Plugin status entries

```json
"plugins": {
    "capa": {"status": "completed", "duration_ms": 1840.2},
    "floss": {"status": "timeout", "error": "ToolTimeout(...)", "duration_ms": 600002.1},
    "diec": {"status": "unavailable", "error": "..."},
    "vtlookup": {"status": "skipped_disabled"}
}
```

Statuses: `completed`, `failed`, `timeout`, `skipped_disabled`,
`skipped_dependency`, `unavailable`. `error` carries `repr(exc)` plus a
truncated traceback for `failed`.

A report therefore distinguishes "no findings" (plugin completed, empty
summary) from "crashed" / "disabled" / "tool missing" / "timed out".

## `result_summary`

One section per plugin that published results. Common patterns:

- Raw output references: `"raw_output_path": "capa/capa_raw_output.json"` -
  always **relative to the run directory**; the file lives at
  `<run_dir>/capa/capa_raw_output.json`.
- Extracted artifacts: `"extracted_to": "resource_overlay/extracted_resources/rsrc_RT_RCDATA_1_1033.bin"` (run-dir-relative).
- Unavailable tools: `{"status": "unavailable", "reason": "..."}`.

## Run directory layout

```
reports/<sanitized-name>_<unix-ts>/
    <name>_statcheck_summary_<ts>.json    JSON report (schema 1.0)
    <name>_statcheck_summary_<ts>.md      Markdown report (if enabled)
    fileinfo/ ... raw artifacts per plugin
    capa/capa_raw_output.json
    resource_overlay/extracted_resources/...
```

## Determinism guarantees

Given the same input file and config, two runs produce byte-identical
`result_summary` sections (after excluding timestamps/run paths), regardless
of `PYTHONHASHSEED` or thread scheduling.
