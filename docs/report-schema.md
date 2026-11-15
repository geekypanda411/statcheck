# Report schema

JSON is the canonical machine-readable report. Markdown renders the same public
metadata and summaries for people, but omits some diagnostic detail such as
full plugin error tracebacks. Analyzer-to-analyzer `internal_context` is not
part of either report.

## Top-level structure

```json
{
  "schema_version": "1.0",
  "metadata": {
    "run": {
      "started_at": "2026-11-15T12:00:00+0000",
      "finished_at": "2026-11-15T12:00:02+0000",
      "duration_ms": 2010.4,
      "target_path": "/samples/example.bin",
      "target_filename": "example.bin",
      "format": "elf",
      "python_version": "3.12.3"
    },
    "analyzed_by": ["fileinfo"],
    "plugins": {
      "fileinfo": {"status": "completed", "duration_ms": 4.2},
      "vtlookup": {"status": "skipped_disabled"}
    }
  },
  "result_summary": {
    "fileinfo": {
      "Filename": "example.bin",
      "File_SHA256": "<64-lowercase-hex-characters>"
    }
  }
}
```

`schema_version` describes this top-level report contract. Within
`result_summary`, sections listed in the reporter's `output_template` come
first; remaining sections are appended in sorted plugin-ID order.

## Metadata

### Run fields

| Field | Meaning |
|---|---|
| `run.started_at` / `run.finished_at` | Local wall-clock timestamps for the analysis phase. |
| `run.duration_ms` | Time from `execute()` start until just before reporting; reporter time is excluded. |
| `run.target_path` / `run.target_filename` | Supplied target path (relative paths are preserved) and basename. The path can reveal local information when sharing reports. |
| `run.format` | Detected or forced format: `pe`, `elf`, `macho`, or `unknown`. |
| `run.python_version` | Interpreter version used for analysis. |
| `analyzed_by` | Sorted IDs whose final plugin status is `completed`. Failed, timed-out, unavailable, and skipped IDs are excluded. |

A completed analyzer can intentionally publish no `result_summary` section—for
example, when there are no strings to inspect—so an ID in `analyzed_by` need not
appear there.

Per-plugin `duration_ms` starts immediately before executor submission and can
include time queued behind workers. It is not necessarily CPU or subprocess
execution time.

### Plugin statuses

| Status | Meaning | Effect on run exit |
|---|---|---|
| `completed` | Analyzer returned without an orchestrator-recognized failure. Findings and optional fields are not guaranteed. | None by itself |
| `failed` | Analyzer raised an exception, or published summary status `failed`. | Exit 1 |
| `timeout` | `ToolTimeout` escaped the analyzer, or its summary declared a timeout such as a YARA engine timeout. | Exit 1 |
| `unavailable` | Expected missing input/tool/service, invalid output, output-limit violation, or parse failure prevented complete analysis. | Exit 1 |
| `skipped_disabled` | Disabled explicitly or by an opt-out analyzer default such as TI. | None |
| `skipped_dependency` | Dependency pruning or deadlock prevented execution. | Pruning alone: none; scheduler deadlock: exit 1 |

Example with detailed diagnostics:

```json
{
  "capa": {"status": "completed", "duration_ms": 1840.2},
  "floss": {
    "status": "timeout",
    "error": "ToolTimeout('floss timed out after 600.0s')",
    "duration_ms": 600002.1
  },
  "diec": {
    "status": "unavailable",
    "error": "diec-info: executable returned code 1",
    "duration_ms": 42.0
  },
  "vtlookup": {"status": "skipped_disabled"}
}
```

For an exception-originated `failed` status, `error` contains `repr(exception)`
and a truncated traceback. For summary-originated `failed`, `timeout`, or
`unavailable`, the orchestrator copies the summary's `reason` or `details`, so a
short actionable error is normal.

The orchestrator also treats reporter write/serialization failures and
dependency deadlocks as run failures. It still attempts remaining reporters, so
a report can exist alongside exit code 1. Early failures such as a missing or
oversized input can occur before a report exists.

## Result summaries

`result_summary` has at most one section per publishing analyzer. Its shape is
analyzer-specific, but these conventions are shared:

```json
{
  "capa": {
    "status": "ok",
    "raw_output_path": "capa/capa_raw_output.json"
  },
  "diec": {
    "status": "unavailable",
    "reason": "diec-info: invalid JSON output",
    "raw_output_path": "diec/diec_raw_output.json"
  }
}
```

- `raw_output_path` is relative to the run directory, never an absolute path.
- Extracted artifact fields such as `extracted_to` are also run-relative.
- `status: unavailable` explains an expected analysis failure; it is different
  from an analyzer that completed and simply found nothing.
- Statuses other than `failed`, `timeout`, and `unavailable` are informational;
  they normally produce plugin metadata status `completed`.

### Interpreting security-sensitive fields

Some negative values are evidence, while others mean analysis was impossible:

- **Authenticode:** `is_signed: false` means a PE was parsed successfully and no
  signature was found. A parse failure instead produces `status: unavailable`
  and `is_signed: null`. Signature `is_valid` can be `"unknown"` when the LIEF
  verifier or trust context cannot decide. `has_timestamp` identifies an
  RFC 3161 `MS_COUNTER_SIGN`; `countersigned` also recognizes the older PKCS #9
  countersignature. Signing time alone is not treated as an RFC 3161 timestamp.
- **ELF overlays:** trailing data is calculated after all recognized file-backed
  ELF headers, tables, sections, and segments. `NOBITS` sections occupy memory,
  not file bytes. Ordinary section-header tables therefore are not overlays;
  malformed structural ranges suppress an overlay claim instead of guessing.
- **ELF linkage:** no `PT_INTERP` alone does not mean static. Dynamic libraries
  and dependency-free shared objects are distinguished from static executables.

Consult the relevant analyzer source under `src/analyzers/` for field-level
semantics not covered by the shared schema.

## Run directory and filenames

```text
<output-dir>/<sanitized-name>_<unix-ts>_<uuid>/
    <sanitized-name>_statcheck_summary_<unix-ts>_<uuid>.json
    <sanitized-name>_statcheck_summary_<unix-ts>_<uuid>.md
    fileinfo/                                      # created on demand
    capa/capa_raw_output.json
    resource_overlay/
        resource_overlay_raw_output.json
        extracted_resources/
            rsrc_<type>_<id>_<lang>_<12-hex-digest>.bin
        extracted_overlay/
            extracted_overlay.bin
```

The complete `<unix-ts>_<uuid>` token is reused in report filenames, not just
the Unix timestamp. The UUID prevents same-name runs started in the same second
from sharing artifacts.

Resource names sanitize the type, ID/name, and language independently. The
12-hex-character digest comes from the raw tuple, distinguishing values that
normalize to the same readable text. Output paths are checked to remain beneath
the extraction directory.

Plugin directories are created **on demand**; a run need not contain a directory
for every discovered plugin.

## Determinism guarantees

Given identical target bytes, config, external-tool/library behavior, remote
responses, rules, and other analyzer inputs:

- summary collections are sorted or otherwise deterministically ordered;
- merged concurrent inputs are sorted before deterministic caps;
- ignored YARA rules are removed before sorting and applying `max_matches`;
- reporter section order follows the template, then sorted orphan IDs.

The guarantee excludes run metadata, generated UUIDs/run paths, and paths
embedded inside summaries. Live TI relations/fuzzy searches, changed external
tool versions, updated YARA/TLD data, and nondeterministic third-party plugins
can legitimately change summaries.
