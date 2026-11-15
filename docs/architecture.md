# Architecture

Statcheck is a **plugin-driven static-analysis pipeline**, not a sandbox and not
an analysis tool by itself. The core discovers analyzers, schedules them in
dependency order, applies shared safety policies, and passes their results to
reporters. Most heavy analysis is performed by Python libraries or external
tools such as capa, FLOSS, Detect It Easy, and YARA.

Use this guide to understand the runtime. See [plugin-api.md](plugin-api.md)
for implementation contracts and [configuration.md](configuration.md) for
settings.

## Mental model

```text
                            +-----------------------------+
CLI arguments ------------> | Configuration and path      |
Target path                 | validation                  |
                            +--------------+--------------+
                                           |
                                           v
                            +-----------------------------+
                            | Input-size guard            |
                            | (before any format parser)  |
                            +--------------+--------------+
                                           |
                                           v
                            +-----------------------------+
                            | Format detection / override |
                            +--------------+--------------+
                                           |
                                           v
                            +-----------------------------+
                            | Plugin discovery and format |
                            | routing                     |
                            +--------------+--------------+
                                           |
                                           v
                            +-----------------------------+
                            | Dependency pruning and DAG  |
                            | scheduling                  |
                            +--------------+--------------+
                                           |
                 +-------------------------+-------------------------+
                 |                                                   |
                 v                                                   v
       +---------------------+                            +---------------------+
       | Python analyzers    |                            | External-tool       |
       | (LIEF, pefile, ...) |                            | analyzers           |
       +----------+----------+                            +----------+----------+
                  |                                                  |
                  |                                         run_tool(): timeout,
                  |                                         output cap, process
                  |                                         process-tree cleanup
                  |                                                  |
                  +------------------------+---------------+---------+
                                           |               |
                                           v               v
                              +-----------------------------+
                              | TargetFile                  |
                              | - result_summary            |
                              | - internal_context          |
                              | - metadata                  |
                              +--------------+--------------+
                                             |
                                             v
                              +-----------------------------+
                              | JSON / Markdown reporters   |
                              +-----------------------------+
```

`internal_context` is used only for analyzer-to-analyzer data exchange. It is
not included in the final JSON report.

## Source map

| Path | Responsibility |
|---|---|
| `main.py` | CLI parsing, early validation, format selection, exit-code mapping. |
| `src/core/orchestrator.py` | Config loading, plugin discovery/routing, DAG pruning/scheduling, run directories, status aggregation, reporting. |
| `src/core/target_file.py` | Target identity, per-run result store, synchronized cached file bytes. |
| `src/core/format_detect.py` | Four-byte magic detection and LIEF-based `CAFEBABE` disambiguation. |
| `src/core/config.py` | Structural and selected common-field validation. |
| `src/core/paths.py` | Project-root and explicit-base path resolution. |
| `src/core/process.py` | External-process deadline, bounded output capture, process-tree cleanup. |
| `src/core/cache.py` | Cache location, atomic JSON writes, tolerant JSON reads. |
| `src/core/http.py` | MalwareBazaar HTTP session and synchronized, bounded TI response caches. |
| `src/core/analysis_utils.py` | Shared entropy, MIME magic, and deterministic collection helpers. |
| `src/analyzers/base_analyzer.py` | Analyzer API, runtime context, defaults, tool resolution, raw-output helper. |
| `src/analyzers/*.py` | Cross-format analyzers. |
| `src/analyzers/pe/`, `src/analyzers/elf/` | Format-specific analyzers. |
| `src/reporters/` | Reporter API and JSON/Markdown implementations. |
| `tests/` | Offline unit and end-to-end tests using temporary output directories. |

## A run, step by step

### 1. CLI and configuration

`main._run()` validates numeric CLI options and target existence, then creates
an `Orchestrator`. Its constructor loads both JSON configs, performs the
supported structural/type checks, and resolves `bin_path` relative to the tool
config.

The input-size guard runs **before format detection**. This matters for
`CAFEBABE` files, which otherwise reach LIEF for Java-class/fat-Mach-O
disambiguation. An oversized CLI target is rejected with exit code 1 before
analysis and before a run directory or report is created.

### 2. Format detection and routing

Auto-detection uses magic bytes and returns `pe`, `elf`, `macho`, or `unknown`.
`--format` bypasses detection for dumps or misleading samples. An `unknown`
format still runs analyzers declaring `supported_formats = ["all"]`.

### 3. Plugin discovery

Discovery recursively imports analyzer files from **all** format directories,
not just the target's directory. Importing everything allows unknown analyzer
IDs in the config to be checked without false warnings for other formats.
Routing then instantiates only analyzers supporting the selected format.

Reporters are discovered from the top-level reporter directory and filtered by
`--report`. Import/deduplication guards are per `Orchestrator` instance;
repeated `load_analyzers()` or `load_reporters()` calls on one instance are
idempotent. Duplicate class names and plugin IDs are filtered.

### 4. Dependency pruning

Before scheduling, disabled plugins receive `skipped_disabled`. The orchestrator
then repeatedly removes plugins whose dependencies cannot be active:

- A missing/disabled ID in `depends["all"]` removes the dependent.
- If no ID in `depends["any"]` remains active, it removes the dependent.
- Removals cascade through the graph and produce `skipped_dependency`.

This is deliberate graph pruning, not an execution failure by itself. In
contrast, an enabled cyclic or otherwise stuck graph is a scheduler deadlock:
it is reported, and the final CLI status is failure.

### 5. Run isolation

At `execute()` entry, the size guard is checked again for programmatic callers.
`TargetFile.reset()` then clears previous summaries, metadata, inter-plugin
context, and cached bytes. Reusing an orchestrator therefore does not reuse
findings or failure statuses.

Each run gets a unique token:

```text
<unix-seconds>_<32-lowercase-hex-uuid>
```

It is used in the run directory and report filenames, preventing same-second
runs from sharing artifacts.

### 6. DAG execution

A `ThreadPoolExecutor` runs independent analyzers concurrently (`10` workers by
default). Threads suit the workload because many analyzers wait on subprocesses,
network requests, or native libraries that release the GIL.

An analyzer becomes ready when:

| Declaration | Runtime requirement |
|---|---|
| `depends = {"all": ["a", "b"], "any": []}` | Every active strict dependency has finished. |
| `depends = {"all": [], "any": ["a", "b"]}` | Every still-active member of the `any` set has finished. At least one had to survive pruning. |

**Dependencies are ordering requirements, not success requirements.** A failed,
timed-out, or unavailable dependency is still finished for scheduling purposes.
Downstream analyzers run and must handle missing or partial context. This keeps
one optional string producer or enrichment source from freezing the rest of the
pipeline.

Per-plugin duration starts immediately before executor submission, so it can
include queue wait. `run.finished_at` and `run.duration_ms` are closed before
report generation; they describe the analysis phase, not total CLI wall time.

### 7. Status aggregation

The orchestrator owns final plugin metadata:

| Analyzer outcome | `metadata.plugins.<id>.status` |
|---|---|
| Normal return, no special summary status | `completed` |
| Summary contains `status: failed`, `timeout`, or `unavailable` | Same status; `reason` or `details` becomes metadata `error` |
| `ToolTimeout` escapes `analyze()` | `timeout` |
| Another exception escapes `analyze()` | `failed`, with repr and truncated traceback |

Other summary values such as `ok`, `analyzed`, or `no_output`, and even no
summary at all, normally mean the analyzer itself completed.

`metadata.analyzed_by` contains only plugins whose final metadata status is
`completed`. A completed plugin need not publish a `result_summary` section.

### 8. Reporting and exit status

Enabled reporters run after analysis, including when all analyzers were disabled
or pruned. Reporter exceptions are logged and remaining reporters are still
attempted.

| Condition | CLI result |
|---|---|
| All analyzers completed or were intentionally skipped; reporting succeeded | `0` |
| Analyzer `failed`, `timeout`, or `unavailable`; dependency deadlock; reporter failure; other runtime failure | `1` |
| Usage or supported config-validation error | `2` |
| Ctrl-C | `130` |

The report can therefore exist and still correctly accompany a nonzero exit.

## Result and artifact model

`TargetFile.results` separates three kinds of state:

| Section | Audience | Lifetime |
|---|---|---|
| `result_summary` | Humans, automation, and LLM consumers | Rendered into reports. |
| `internal_context` | Downstream analyzers | Per-run only; omitted from canonical JSON. |
| `metadata` | Run diagnostics and status | Rendered into reports. |

Analyzers write raw artifacts under `<run_dir>/<plugin_id>/` on demand.
`BaseAnalyzer.save_raw()` returns a run-directory-relative path. Relative links
keep reports movable; deterministic section and collection ordering keeps
summaries comparable. Full reports still contain variable timings, UUIDs, and
supplied target-path metadata, so byte-identical claims apply only as described in
[report-schema.md](report-schema.md#determinism-guarantees).

## External-process lifecycle

All built-in external tools use `run_tool()` rather than calling
`subprocess.run()` directly:

1. Start the tool in a new process group/session where supported.
2. Read stdout and stderr on separate threads, retaining at most the configured
   cap for each stream while draining excess data to avoid pipe deadlocks.
3. Apply one wall-clock deadline to the direct child **and** descendants that
   keep inherited output pipes open.
4. On timeout, terminate the process tree and raise `ToolTimeout`; on
   interruption, perform the same cleanup and propagate the interruption.
5. If the direct child exits successfully but background descendants remain,
   clean up that process group before returning. Plugins must not rely on
   background children surviving `run_tool()`.
6. Excess output or an ordinary tool error raises `ToolError`; built-in
   analyzers turn expected tool failures into `unavailable` summaries.

Ctrl-C cancels queued analyzer futures. The executor waits for already-running
analyzers to finish or be interrupted before `execute()` unwinds, preventing late
writes after the run has ended.

## Caching and concurrency boundaries

- **Target bytes:** loaded at most once per run; a lock prevents two analyzers
  from simultaneously allocating duplicate whole-file reads.
- **TI responses:** exact-hash responses use a provider-specific JSON index.
  Thread and file locks protect the read/fetch/write transaction. Expired and
  malformed entries are pruned, and at most 1024 recent entries per provider are
  retained. Atomic replacement prevents partially written JSON.
- **Live TI queries:** VT relations/fuzzy searches and MalwareBazaar fuzzy
  pivots are not served from that cache.
- **YARA rules:** compiled rules are reused within a process using path, mode,
  file sizes, and modification times in the cache key.
- **Run outputs:** unique run tokens prevent independent processes from sharing
  an output directory.

## Design decisions and rationale

| Decision | Rationale |
|---|---|
| Split summaries, raw artifacts, and internal context | Keeps reports useful to people/LLMs without discarding evidence or exposing large intermediate data. |
| Centralize subprocess handling | Gives every tool the same deadline, output, and cleanup behavior instead of relying on each plugin. |
| Make TI opt-in through `enabled_by_default = False` | A missing config must never silently disclose hashes to third parties. |
| Use runtime context rather than expanding `analyze()` | Supplies paths/timeouts/limits while preserving the third-party analyzer signature. |
| Treat dependencies as completion ordering | Allows partial analysis when an optional producer fails. |
| Sort before deterministic caps | Prevents thread scheduling or hash seeds from changing which findings survive a limit. |
| Store run-relative artifact paths | Lets report directories be moved or shared without breaking links. |
| Use unique run IDs and reset per-run state | Prevents cross-run artifact and result contamination. |

For concrete implementation examples, continue with the [plugin API](plugin-api.md).
