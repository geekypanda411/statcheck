# Security notes

**Statcheck performs static analysis; it does not run the target as a program.**
The sample, parser output, external tools, remote services, and generated
artifacts still cross separate trust boundaries.

## Trust boundaries

- Treat samples, YARA rules, and extracted content as hostile. Python parsers
  and third-party executables process untrusted file structures with the
  statcheck user's privileges.
- Treat configured binaries, `bin_path`, `PATH`, plugins, and config files as
  trusted inputs. Statcheck does not sandbox external tools or restrict their
  filesystem, process, or network access.
- Prefer a disposable VM for real malware. A non-root container reduces
  privileges but is not a complete boundary against malicious-file parser or
  kernel vulnerabilities.
- Handle extracted resources/overlays as potential malware. Raw JSON and
  Markdown are evidence files, not sanitized or safe-to-render content.

## Network inventory

The built-in runtime analyzers initiate only the following application
requests. Exact-hash cache hits avoid their corresponding request; relations
and fuzzy pivots are never disk-cached.

| Source | Destination and trigger | Data sent |
|---|---|---|
| `iocextractor` | GET `https://data.iana.org/TLD/tlds-alpha-by-domain.txt` when extraction has strings and the TLD list is missing/stale | No sample path, bytes, hashes, or other sample data |
| `vtlookup` | VirusTotal exact-hash lookup when explicitly enabled; optional live relations and SSDeep search | SHA-256; optionally the same hash in relation requests and the SSDeep value in a search query. API credentials go to VT |
| `malwarebazaar` | POST to `base_url` when explicitly enabled; optional live TLSH/ImpHash pivots | SHA-256 for exact lookup; optionally TLSH/ImpHash. The API key is sent in `Auth-Key` |

The built-in lookups do not upload sample bytes. Nevertheless, hashes and
similarity values can identify sensitive samples. Keep both TI plugins disabled
unless disclosure is acceptable, and remember that each requires explicit
`"enabled": true`.

MalwareBazaar `base_url` changes where **both its hashes and API key** are sent;
use only a trusted endpoint. The VT analyzer has no `base_url` override.
Third-party tool binaries are outside statcheck's network control.

Separately, manually running [`scripts/fetch-tools.sh`](../scripts/fetch-tools.sh)
contacts GitHub to download pinned capa and FLOSS releases; see
[`bin/README.md`](../bin/README.md).

## Sensitive files and output

- Exact-hash TI responses are stored in `$XDG_CACHE_HOME/statcheck/ti/`
  (or `~/.cache/statcheck/ti/`). The JSON cache keys contain the SHA-256 hash,
  and the values contain provider responses. Live relation/fuzzy results can
  also be written to reports and, where collected by the analyzer, raw output.
  Cache files are locked during updates,
  pruned by TTL, and capped at 1024 entries per provider; locking is not
  encryption or access control.
- Statcheck does not add API keys to reports, logs, or cache entries. Protect
  environment variables and the gitignored `.env`, and avoid placing secrets in
  untrusted tool arguments or endpoints.
- `metadata.run.target_path` preserves the supplied target path (often an
  absolute local path). Logs and third-party/raw outputs can also contain local
  paths, filenames, strings, IOCs, hashes, YARA match data, and complete TI
  responses. Review and sanitize reports, raw JSON, logs, caches, and extracted
  artifacts before sharing. IOC `defang` alone does not sanitize a report.
- A custom IOC `tld_file` may be outside the cache and is rewritten on a
  successful update. TLD metadata remains in the cache; the runtime never
  writes `tools_config.json`.

Erase run directories and cache data according to the sensitivity of the
original sample and the remote responses.

## Resource guards are not sandboxing

- `max_file_bytes` rejects an oversized target **before format detection,
  analyzer execution, or external tool execution**. This path exits 1 and does
  not create an analysis report.
- Subprocess stdout/stderr caps, raw JSON thresholds, IOC caps, and extraction
  budgets limit specific outputs. They do not cap every allocation, every file
  a tool may write, total concurrent resource use, or network activity. Raw
  JSON is serialized before its character threshold is checked.
- External subprocesses have deadlines and bounded captured output. Descendant
  processes that inherit stdout/stderr are covered by the **same wall-clock
  deadline**, even if the direct child exits first. Process-tree/group cleanup
  is also attempted after a successful direct-child exit, including when
  descendants redirected the captured streams. Cleanup on timeout,
  interruption, or normal exit is best-effort OS process management, not
  isolation.

Use OS-level memory, CPU, filesystem, and network controls where hard limits
are required. Configuration details are in the
[configuration reference](configuration.md).

## Tool provisioning

`scripts/fetch-tools.sh` downloads only the pinned **Linux x86-64** capa
v10.0.0 and FLOSS v3.2.0 ZIP releases. For newly downloaded archives it
automatically verifies the script's pinned SHA-256 digest before extracting and
marking the binary executable. An existing destination is skipped untouched
and is **not re-verified or overwritten**.

The script does not provision DiE, QuantumStrand, or YARA rules; obtain and
verify those manually from trusted sources. See
[`bin/README.md`](../bin/README.md) for exact names and commands.
